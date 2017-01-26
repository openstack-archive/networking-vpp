# Copyright (c) 2016 Cisco Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from abc import ABCMeta
from abc import abstractmethod
import etcd
import eventlet
from oslo_log import log as logging
import six
import time
import traceback
from urllib3.exceptions import TimeoutError as UrllibTimeoutError

LOG = logging.getLogger(__name__)


class EtcdElection(object):
    def __init__(self, etcd_client, name, election_path=None,
                 thread_id=None,
                 recovery_time=5):
        self.etcd_client = etcd_client
        self.name = name
        # A unique value that identifies each worker thread
        self.thread_id = thread_id
        # Sleeping threads wake up after this time and
        # check if a master is alive and one of them will become the master
        # if the current master key has expired
        self.recovery_time = recovery_time
        if election_path:
            self.master_key = election_path + "/master_%s" % self.name

    def wait_until_elected(self):
        """Elect a master thread among a group of worker threads.

        Election Algorithm:-
        1) Each worker thread is assigned a unique thread_id at launch time.
        2) All threads start the election process by running this method.
        3) An etcd master key, whose value equals its thread_id, with a TTL
           equal to the recovery_time, controls the master election process.
        3) The thread that first succeeds in atomically writing its ID
           to the etcd master key, becomes the master. The
           remaining threads and go to sleep after a master has been elected.
        4) The master thread then breaks out of the election loop and
           starts doing work. It periodically refreshes the TTL value
           of its key in etcd to let other threads know that it is alive.
           It is rather important that it's work takes less than the
           heartbeat time *if* there must be only one thread running.
           It is not so much of a concern if there can be multiple threads
           running and this is just to keep the active thread count down.
        5) The sleeping threads periodically wake up every recovery_time
           to check if the master is alive. If the master key is absent,
           in etcd, they trigger a re-election and elect a new master,
           which begins doing the work.

        name - A common thread name for the group of threads
               that need to elect a master. For e.g.: forward_worker
        thread_id - A unique thread id assigned to each thread in the group
        recovery_time - Controls the master-key TTL and how often the
                        health of master is checked by the worker threads
        """
        # Start the election
        while True:
            try:
                # Attempt to become master
                self.etcd_client.write(self.master_key,
                                       self.thread_id,
                                       prevExist=False,
                                       ttl=self.recovery_time)
                LOG.debug("current master for %s threads is thread_id %s",
                          self.name, self.thread_id)
                # if successful, the master breaks to start doing work
                break
            # An etcdException means some other thread has already become
            # the master
            except etcd.EtcdException:
                try:
                    # Refresh TTL if master == us, then break to do work
                    self.etcd_client.write(self.master_key,
                                           self.thread_id,
                                           prevValue=self.thread_id,
                                           ttl=self.recovery_time)
                    break
                # All non-master threads will end up here, sleep for
                # recovery_time and become master if the current master
                # is dead
                except etcd.EtcdException:
                    eventlet.sleep(self.recovery_time)


@six.add_metaclass(ABCMeta)
class EtcdWatcher(EtcdElection):
    # There's a thread election here because we want to keep the number
    # of equivalent watcher threads down as we are generally running
    # with multiple processes.

    # NB: worst case time between ticks is heartbeat + DANGER_PAUSE seconds
    # or the length of a read (which should be fast)

    # We wait this long after an etcd exception in watch_forever, in
    # case it's going wrong repeatedly.  This prevents a runaway CPU
    # eater.
    DANGER_PAUSE = 2

    def __init__(self, etcd_client, name, watch_path, election_path=None,
                 thread_id=None, wait_until_elected=False, recovery_time=5,
                 data=None, heartbeat=60):
        super(EtcdWatcher, self).__init__(etcd_client, name, election_path,
                                          thread_id,
                                          recovery_time)
        self.etcd_client = etcd_client
        self.tick = None
        self.name = name
        self.watch_path = watch_path
        self.data = data
        self.heartbeat = heartbeat
        # The _wait_until_elected is a switch that controls whether the
        # threads need to wait to do work until elected. Note that the agent
        # watcher threads do not require waiting for an election and as a
        # result, the this is set to False
        self._wait_until_elected = wait_until_elected

    @abstractmethod
    def resync(self):
        pass

    @abstractmethod
    def do_work(self, action, key, value):
        pass

    def do_tick(self):
        # override me!
        pass

    def watch_forever(self):
        """Watch a keyspace forevermore

        This may not exit - if there are errors they're logged (and in case
        they are persistent we pause).
        """

        while True:
            try:
                self.do_tick()
                if self._wait_until_elected:
                    self.wait_until_elected()
                self.do_watch()
            except Exception as e:
                LOG.warning('%s: etcd threw exception %s',
                            self.name, traceback.format_exc(e))
                # In case of a dead etcd causing continuous
                # exceptions, the pause here avoids eating all the
                # CPU
                time.sleep(self.DANGER_PAUSE)

    def do_watch(self):
        """Watch a keyspace

        This will conduct one watch or one read.
        """

        try:
            LOG.debug("%s: pausing", self.name)

            try:
                if self.tick is None:
                    # We have no state, so we have effectively
                    # 'fallen off of the history' and need to
                    # resync in full.
                    raise etcd.EtcdEventIndexCleared()
                # Current versions of python-etcd use the timeout in
                # interesting ways.  Slow URL connections + no data
                # to return can lead to timeouts much longer than you
                # might expect.  So we watch for a timeout for
                # ourselves as well.

                # Here, we use both etcd Client timeout and eventlet timeout
                # As etcd.Client timeout is not reliable, enforce
                # the timeout with eventlet.Timeout
                # Most of the time, we timeout thanks to etcd client,
                # if we timeout due to eventlet, we have an ugly error message
                with eventlet.Timeout(self.heartbeat + 5):
                    rv = self.etcd_client.watch(self.watch_path,
                                                recursive=True,
                                                index=self.tick,
                                                timeout=self.heartbeat)

                vals = [rv]

                next_tick = rv.modifiedIndex + 1

            except etcd.EtcdEventIndexCleared:
                # We can't follow etcd history in teaspoons, so
                # grab the current state and implement it.

                LOG.debug("%s: resyncing in full", self.name)
                rv = self.etcd_client.read(self.watch_path,
                                           recursive=True)

                # This appears as if all the keys have been updated -
                # because we can't tell which have been and which haven't.
                vals = rv.children

                self.resync()

                next_tick = rv.etcd_index + 1

                LOG.debug("%s watch index recovered: %s",
                          self.name, str(next_tick))

            for kv in vals:

                LOG.debug("%s: active, key %s", self.name, kv.key)

                try:
                    self.do_work(kv.action, kv.key, kv.value)
                except Exception:
                    LOG.exception('%s key %s value %s could not be processed'
                                  % (kv.action, kv.key, kv.value))
                    # TODO(ijw) raise or not raise?  This is probably
                    # fatal and incurable.
                    raise

            # Update the tick only when all the above completes so that
            # exceptions don't cause the count to skip before the data
            # is processed
            self.tick = next_tick

        except (etcd.EtcdWatchTimedOut, UrllibTimeoutError, eventlet.Timeout):
            # This is normal behaviour, indicating either a watch timeout
            # (nothing changed) or a connection timeout (we should retry)
            pass

        # Other exceptions are thrown further, but a sensible background
        # thread probably catches them rather than terminating.
