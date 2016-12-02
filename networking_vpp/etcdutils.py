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


@six.add_metaclass(ABCMeta)
class EtcdWatcher(object):
    # NB: worst case time between ticks is heartbeat + DANGER_PAUSE seconds
    # or the length of a read (which should be fast)

    # We wait this long after an etcd exception in watch_forever, in
    # case it's going wrong repeatedly.  This prevents a runaway CPU
    # eater.
    DANGER_PAUSE = 2

    def __init__(self, etcd_client, name, watch_path, data=None, heartbeat=60):
        self.etcd_client = etcd_client
        self.tick = None
        self.name = name
        self.watch_path = watch_path
        self.data = data
        self.heartbeat = heartbeat
        pass

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
                self.do_watch()
            except Exception as e:
                LOG.warning('%s: etcd threw exception %s',
                            (self.name, traceback.format_exc(e)))
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
                with eventlet.Timeout(self.heartbeat):
                    rv = self.etcd_client.watch(self.watch_path,
                                                recursive=True,
                                                index=self.tick)

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
>                                  % (kv.action, kv.key, kv.value))
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


class SystemKeys(object):
    """Etcd keys for the entire system

    In etcd, the layout is:
    LEADIN/nodes - subdirs are compute nodes
    LEADIN/nodes/X/ports - entries are JSON-ness containing
    all information on each bound port on the compute node.
    (Unbound ports are homeless, so the act of unbinding is
    the deletion of this entry.)
    LEADIN/state/nodes/X - return state of the VPP
    LEADIN/state/nodes/X/alive - heartbeat back
    LEADIN/state/nodes/X/ports - port information.
    LEADIN/state/nodes/X/physnets - physnets on node
    Specifically a key here (regardless of value) indicates
    the port has been bound and is receiving traffic.
    """


    def __init__(self):
        self.leadin = '/networking-vpp'  # TODO(ijw): make configurable?
        self.state_key_space = self.leadin + '/state'
        self.port_key_space = self.leadin + '/nodes'


class HostKeys(SystemKeys):
    """Etcd keys for a single host."""

    def __init__(self, host):
        # The agent writes these keys
        self.host_state_key_space = self.state_key_space + "/%s" % self.host
        self.port_state_key_space = self.host_state_key_space + '/ports'
        self.binding_key_space = self.host_state_key_space + '/bindings'
        self.physnet_key_space = self.host_state_key_space + '/physnets'

        # The driver writes these keys
        self.instruction_key_space = (self.port_key_space + "/%s/ports" % self.host)

    def host_alive_key(self):
        return self.host_state_key_space + '/alive'

    def port_state_key(self, port):
        return self.instruction_key_space + '/' + port

    def binding_key(self, port):
        return self.binding_key_space + '/' + port

    def physnet_key(self, physnet):
        return self.physnet_key_space + '/' + physnet

class EtcdHelper(object):

    def __init__(self, client):
        self.etcd_client = client

    def clear_leaf_keys(self, key_space):
        """Clear the keys in this bit of the key_space"""
        LOG.debug("Clearing key space: %s", key_space)
        try:
            rv = self.etcd_client.read(key_space)
            for child in rv.children:
                self.etcd_client.delete(child.key)
        except EtcdNotFile:
            # Can't delete directories - they're harmless anyway
            pass

    def mkdir(self, path):
        try:
            self.etcd_client.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass

    def update(self, k, v):
        """Update an etcd key

        This is like an etcd write, but it has special properties - it
        will create a key if it must be created, set its value
        accordingly, and if the value is None it will delete the key
        (not worrying too much if the key's already gone away).

        """
        
        try:
            # not needed? - do_etcd_mkdir('/'.join(k.split('/')[:-1]))
            if v is None:
                LOG.debug('deleting key %s', k)
                try:
                    self.etcd_client.delete(k)
                except etcd.EtcdKeyNotFound:
                    # The key may have already been deleted
                    # no problem here
                    pass
            else:
                LOG.debug('writing key %s', k)
                self.etcd_client.write(k, json.dumps(v))
            return True
        except Exception:       # TODO(ijw) select your exceptions
            return False

