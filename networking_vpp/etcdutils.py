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
import atexit
import etcd
import eventlet
import eventlet.semaphore
from oslo_log import log as logging
import six
import time
import traceback
from urllib3.exceptions import TimeoutError as UrllibTimeoutError
import uuid

LOG = logging.getLogger(__name__)

elector_cleanup = []


@atexit.register
def cleanup_electors():
    for f in elector_cleanup:
        f.clean()


class EtcdElection(object):
    def __init__(self, etcd_client, name, election_path,
                 work_time,
                 recovery_time=5,
                 multi_worker_ok=False):
        """Participant in a leader election via etcd datastore.

        etcd_client: the client handle for dealing with etcd

        name: the category name - we elect one leader of this type

        election_path: the location where we conduct elections in etcd

        work_time: the typical time the leader spends doing work.
        It remains elected for this long without conducting another
        election.

        recovery_time: the time, after we're certain the leader has
        stopped doing work, that is the longest we want to wait before
        someone else takes over if the leader has died (Note that
        this means you can be without a working leader for work_time
        + recovery_time if the leader crashes just after winning the
        election)

        multi_worker_ok: True if you'd prefer to favour having at least
        one elected leader over having no more than one elected leader.
        Typically this will cause a second leader to start working even
        if the original still believes it's elected, and is useful if
        that's more likely to reduce pauses.
        """

        self.etcd_client = etcd_client
        self.name = name
        # A unique value that identifies each worker thread
        self.thread_id = str(uuid.uuid4())
        # Sleeping threads wake up after this time and
        # check if a master is alive and one of them will become the master
        # if the current master key has expired
        self.recovery_time = recovery_time

        # Threads hold the lock for this lng because this is the most
        # work they will do.
        self.work_time = work_time
        self.master_key = election_path + "/master_%s" % self.name

        # We recommend you configure these log levels
        # etcd_log = logging.getLogger('etcd.client')
        # etcd_log.setLevel(logging.logging.WARNING)
        # LOG.setLevel(logging.logging.INFO)

        global elector_cleanup
        elector_cleanup.append(self)

    def wait_until_elected(self):
        """Elect a master thread among a group of worker threads.

        Election Algorithm:-
        1) Each worker thread is assigned a unique thread_id at launch time.
        2) All threads start the election process by running this method.
        3) An etcd master key, whose value equals its thread_id, with a TTL
           equal to the work_time, controls the master election process.
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

        """
        # Start the election
        attempt = 0
        while True:
            attempt = attempt + 1
            # LOG.debug('Thread %s attempting to get elected for %s, try %d',
            #           self.thread_id, self.name, attempt)
            try:
                # Attempt to become master
                self.etcd_client.write(self.master_key,
                                       self.thread_id,
                                       prevExist=False,
                                       ttl=self.work_time)
                LOG.debug("new master for %s threads is thread_id %s",
                          self.name, self.thread_id)
                # if successful, the master breaks to start doing work
                break
            # An etcdException means some other thread has already become
            # the master
            except etcd.EtcdException:
                try:
                    # LOG.debug('Thread %s refreshing master for %s, try %d',
                    #           self.thread_id, self.name, attempt)

                    # Refresh TTL if master == us, then break to do work
                    # TODO(ijw): this can be a refresh
                    self.etcd_client.write(self.master_key,
                                           self.thread_id,
                                           prevValue=self.thread_id,
                                           ttl=self.work_time)
                    LOG.debug('Thread %s refreshed master for %s, try %d',
                              self.thread_id, self.name, attempt)
                    break
                # All non-master threads will end up here, watch for
                # recovery_time (in case some etcd connection fault means
                # we don't get a watch notify) and become master if the
                # current master is dead
                except etcd.EtcdException:
                    # LOG.debug('Thread %s failed to elect and is '
                    #           'waiting for %d secs, group %s, try %d',
                    #           self.thread_id, self.recovery_time,
                    #           self.name, attempt)

                    try:
                        with eventlet.Timeout(self.recovery_time + 5, False):
                            self.etcd_client.watch(
                                self.master_key,
                                timeout=self.recovery_time)
                    except etcd.EtcdWatchTimedOut:
                        pass
                    except etcd.EtcdException:
                        eventlet.sleep(self.recovery_time)

    def clean(self):
        """Release the election lock if we're currently elected.

        This happens on process exit to speed up the re-election.
        """
        try:
            self.etcd_client.delete(self.master_key,
                                    self.thread_id,
                                    prevValue=self.thread_id)
        except etcd.EtcdException:
            pass


@six.add_metaclass(ABCMeta)
class EtcdWatcher(object):
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
                 wait_until_elected=False, recovery_time=5,
                 data=None, heartbeat=60):

        # NB: heartbeat + recovery + DANGER_PAUSE + whatever work you do is
        # the loop total time.  This is important if we're going to
        # do elections and we need to allow this quantity of time
        # before the election lapses.

        self.etcd_client = etcd_client
        self.tick = None
        self.name = name
        self.watch_path = watch_path
        self.data = data
        self.heartbeat = heartbeat

        # The wait_until_elected is a switch that controls whether the
        # threads need to wait to do work until elected. Note that the agent
        # watcher threads do not require waiting for an election and as a
        # result, the this is set to False
        if wait_until_elected:
            work_time = heartbeat + self.DANGER_PAUSE + recovery_time

            self.etcd_elector = EtcdElection(etcd_client, name, election_path,
                                             work_time=work_time,
                                             recovery_time=recovery_time)
        else:
            self.etcd_elector = None

        # Explicitly a semaphore, because we don't monkey patch 'threading'
        # in the agent and can't use threading.Lock
        self.etcd_data_lock = eventlet.semaphore.Semaphore()
        self.etcd_data = None

        # Get the initial state of etcd.
        self.refresh_all_data()

    def do_work(self, action, key, value):
        """Process an indiviudal update received in a watch

        Override this if you can deal with individual updates given
        their location.  Leave it if all updates involve rereading all
        downloaded data.

        etcd_data is current when called and will not change during
        the call.
        """
        self.do_all_work()

    @abstractmethod
    def do_all_work(self):
        """Process all updates from a refreshing read or a watch

        This may happen on startup, on lost history or if the reader has no
        better way to behave than checking all data.

        etcd_data is current when called and will not change during
        the call.
        """
        pass

    def do_tick(self):
        """Do background tasks that can happen between etcd updates.

        Will be called once per (heartbeat + result processing time)
        """
        pass

    def refresh_all_data(self):
        """Load the entirety of the data we're watching from etcd.

        This is used on initialisation and when history is lost.  It
        also causes work for keys that changed.

        """

        LOG.debug("%s: resyncing in full", self.name)
        rv = self.etcd_client.read(self.watch_path,
                                   recursive=True)

        with self.etcd_data_lock:
            self.etcd_data = {}
            for f in rv.children:
                self.etcd_data[f.key] = f.value

            self.do_all_work()

        # TODO(ijw): there's a better number to use here
        self.tick = rv.etcd_index + 1

        LOG.debug("%s watch index recovered: %s",
                  self.name, rv.modifiedIndex)

    def watch_forever(self):
        """Watch a keyspace forevermore

        This may not exit - if there are errors they're logged (and in case
        they are persistent we pause).
        """

        while True:
            try:
                self.do_tick()
                if self.etcd_elector:
                    self.etcd_elector.wait_until_elected()
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
                with eventlet.Timeout(self.heartbeat + 5, False):
                    rv = self.etcd_client.watch(self.watch_path,
                                                recursive=True,
                                                index=self.tick,
                                                timeout=self.heartbeat)

                if rv:
                    with self.etcd_data_lock:

                        # The processing function is entitled to check all etcd
                        # data.  Update it before we call the processor.
                        if rv.action == 'delete':
                            del self.etcd_data[rv.key]
                        else:
                            self.etcd_data[rv.key] = rv.value

                        # We can, in the case of a watch, hint at where the
                        # update went.

                        try:
                            self.do_work(rv.action, rv.key, rv.value)
                        except Exception:
                            LOG.exception(('%s key %s value %s could'
                                          'not be processed')
                                          % (rv.action, rv.key, rv.value))
                            # TODO(ijw) raise or not raise?  This is probably
                            # fatal and incurable, because we will only repeat
                            # the action on the next round.
                            raise

                    # Update the tick only when all the above completes so that
                    # exceptions don't cause the count to skip before the data
                    # is processed
                    self.tick = rv.modifiedIndex + 1

            except etcd.EtcdEventIndexCleared:
                # We can't follow etcd history in teaspoons, so
                # grab the current state in its entirety.

                self.refresh_all_data()

        except (etcd.EtcdWatchTimedOut, UrllibTimeoutError, eventlet.Timeout):
            # This is normal behaviour, indicating either a watch timeout
            # (nothing changed) or a connection timeout (we should retry)
            pass

        # Other exceptions are thrown further, but a sensible background
        # thread probably catches them rather than terminating.


@six.add_metaclass(ABCMeta)
class EtcdChangeWatcher(EtcdWatcher):
    """An etcd watcher framework that notifies only discrete changes

    This deals with the start/resync/watch dilemmas and makes a single
    'this key has changed' call regardless of what prompts it.
    It does this by remembering what it's notified (via key_changed) in
    the past, and avoiding any notification that amounts to 'this key has
    changed to the same value'.  However, when we have to do a full resync
    the ordering of key updates is not guaranteed.
    """

    def __init__(self, etcd_client, name, watch_path, election_path=None,
                 wait_until_elected=False, recovery_time=5,
                 data=None, heartbeat=60):
        self.implemented_state = {}

        super(EtcdChangeWatcher, self).__init__(
            etcd_client, name, watch_path, election_path,
            wait_until_elected, recovery_time,
            data, heartbeat)

    def do_all_work(self):
        """Reimplement etcd state pending a change of some of it

        Some undefined quantity of etcd's data has changed.
        Work out what we've implemented, and re-implement the
        remainder.
        """

        # First, spot keys that went away

        in_keys = set(self.etcd_data.keys())
        impl_keys = set(self.implemented_state.keys())

        deleted_keys = impl_keys - in_keys
        new_keys = in_keys - impl_keys
        existing_keys = in_keys & impl_keys

        for k in deleted_keys:
            # Note: this will change implemented_state
            self.do_work('delete', k, None)

        for k in new_keys:
            self.do_work('add', k, self.etcd_data[k])

        for k in existing_keys:
            if self.implemented_state[k] != \
               self.etcd_data[k]:
                self.do_work('change', k, self.etcd_data[k])

    def do_work(self, action, key, value):
        """Implement etcd state when it changes

        This implements the state in VPP and notes the key/value
        that VPP has implemented in self.implemented_state.
        """
        self.key_change(action, key, value)
        if action == 'delete':
            try:
                del self.implemented_state[key]
            except KeyError:
                # If for any reason we see a double-delete that's fine
                pass
        else:
            self.implemented_state[key] = value

    @abstractmethod
    def key_change(self, action, key, value):
        pass
