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
from oslo_config import cfg
from oslo_log import log as logging
import re
import six
import time
import typing  # noqa
from urllib3.exceptions import TimeoutError as UrllibTimeoutError
import uuid

from networking_vpp._i18n import _
from networking_vpp import exceptions as vpp_exceptions
from networking_vpp import jwt_agent

from oslo_serialization import jsonutils


LOG = logging.getLogger(__name__)

ETC_HOSTS_DELIMITER = ','
ETC_PORT_HOST_DELIMITER = ':'


@six.add_metaclass(ABCMeta)
class EtcdWriter(object):

    @abstractmethod
    def _process_read_value(self, key, value):
        """Turn a string from etcd into a value in the style we prefer

        May parse, validate and/or otherwise modify the result.
        """

        pass

    @abstractmethod
    def _process_written_value(self, key, value):
        """Turn a value into a serialised string to store in etcd

        May serialise, sign and/or otherwise modify the result.
        """
        pass

    def __init__(self, etcd_client):
        self.etcd_client = etcd_client

    def write(self, key, data, *args, **kwargs):
        """Serialise and write a single data key in etcd.

        The value is received as a Python data structure and stored in
        a conventional format (serialised to JSON, in this class
        instance).

        """
        data = self._process_written_value(key, data)

        self.etcd_client.write(key, data, *args, **kwargs)

    def read(self, *args, **kwargs):
        """Watch and parse a data key in etcd.

        The value is stored in a conventional format (serialised
        somehow) and we parse it to Python.  This may throw an
        exception if the data cannot be read when .value is called on
        any part of the result.

        """
        return ParsedEtcdResult(self,
                                self.etcd_client.read(*args, **kwargs))

    def watch(self, *args, **kwargs):
        """Watch and parse a data key in etcd.

        The value is stored in a conventional format (serialised
        somehow) and we parse it to Python.  This may throw an
        exception if the data cannot be read when .value is called on
        any part of the result.

        """

        return ParsedEtcdResult(self,
                                self.etcd_client.watch(*args, **kwargs))

    def delete(self, key):
        # NB there's no way of clearly indicating that a delete is
        # legitimate - the parser has no role in it, here.

        # We do augment the delete to delete more throroughly.  This
        # should probably be a mixin.
        try:
            self.etcd_client.delete(key)
        except etcd.EtcdNotFile:
            # We are asked to delete a directory as in the
            # case of GPE where the empty mac address directory
            # needs deletion after the key (IP) has been deleted.
            try:
                # TODO(ijw): define semantics: recursive delete?
                self.etcd_client.delete(key, dir=True)
            except Exception:  # pass any exceptions
                pass
        except etcd.EtcdKeyNotFound:
            # The key may have already been deleted
            # no problem here
            pass


def _unchanged(name):
    def pt_get(self):
        return getattr(self._result, name)

    return property(pt_get)


class ParsedEtcdResult(etcd.EtcdResult):
    """Parsed version of an EtcdResult

    An equivalent to EtcdResult that processes its values using the
    parser that the reading class implements.
    """

    def __init__(self, reader, result):

        self._reader = reader
        self._result = result

    # A whole set of result properties are as they are on the original
    # result.

    key = _unchanged('key')
    expiration = _unchanged('expiration')
    ttl = _unchanged('ttl')
    modifiedIndex = _unchanged('modifiedIndex')
    createdIndex = _unchanged('createdIndex')
    newKey = _unchanged('newKey')
    dir = _unchanged('dir')
    etcd_index = _unchanged('etcd_index')
    raft_index = _unchanged('raft_index')
    action = _unchanged('action')

    # support iteration over result's children
    children = _unchanged('children')

    # used internally by etcd.client.Client
    _prev_node = _unchanged('_prev_node')

    # The one special case, where we need to change things
    @property
    def value(self):
        return self._reader._process_read_value(self._result.key,
                                                self._result.value)

    def get_subtree(self, *args, **kwargs):
        for f in self._result.get_subtree(*args, **kwargs):
            # This returns a value which may itself have a subtree
            # depending on args passed

            return ParsedEtcdResult(self._reader, f)

    # We know a bit too much about the internals of EtcdResult, but
    # given that, we know that the internals all work from .value or
    # .get_subtree() and the rest of the calls should use parsed
    # result values.


def json_writer(etcd_client):
    if cfg.CONF.ml2_vpp.jwt_signing:
        return SignedEtcdJSONWriter(etcd_client)
    else:
        return EtcdJSONWriter(etcd_client)


class EtcdJSONWriter(EtcdWriter):
    """Write Python datastructures to etcd in a consistent form.

    This takes values (typically as Python datastructures) and
    converts them using JSON serialisation to a form that can be
    stored in etcd, and vice versa.

    """

    def __init__(self, etcd_client):
        super(EtcdJSONWriter, self).__init__(etcd_client)

    def _process_read_value(self, key, value):
        value = jsonutils.loads(value)
        return value

    def _process_written_value(self, key, value):
        return jsonutils.dumps(value)


class SignedEtcdJSONWriter(EtcdJSONWriter):
    """Write Python datastructures to etcd in a consistent form.

    This takes values (typically as Python datastructures) and
    converts them using JSON serialisation to a form that can be
    stored in etcd, and vice versa.

    """

    def __init__(self, etcd_client):
        self.jwt_agent = jwt_agent.JWTUtils(
            cfg.CONF.ml2_vpp.jwt_node_cert,
            cfg.CONF.ml2_vpp.jwt_node_private_key,
            cfg.CONF.ml2_vpp.jwt_ca_cert,
            cfg.CONF.ml2_vpp.jwt_controller_name_pattern)
        super(SignedEtcdJSONWriter, self).__init__(etcd_client)

    def _process_read_value(self, key, value):
        value = jsonutils.loads(value)
        if (self.jwt_agent.should_path_be_signed(key)):
            signerNodeName = self.jwt_agent.get_signer_name(key)
            value = self.jwt_agent.verify(signerNodeName,
                                          key,
                                          value)
        return value

    def _process_written_value(self, key, value):
        if (self.jwt_agent.should_path_be_signed(key)):
            value = self.jwt_agent.sign(key, value)
        return jsonutils.dumps(value)


elector_cleanup = []  # type: typing.List[EtcdElection]


@atexit.register
def cleanup_electors():
    for f in elector_cleanup:
        f.clean()


class EtcdElectionLost(Exception):
    pass


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
        """Wait indefinitely until we are the only master among a pool of workers.

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
        attempt = 0
        while True:
            attempt += 1
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
                    # We may already be the master.  Extend the election time.
                    self.extend_election(self.work_time)

                    LOG.debug('Thread %s refreshed master for %s for try %d',
                              self.thread_id, self.name, attempt)
                    break
                # All non-master threads will end up here, watch for
                # recovery_time (in case some etcd connection fault means
                # we don't get a watch notify) and become master if the
                # current master is dead
                except EtcdElectionLost:
                    try:
                        with eventlet.Timeout(self.recovery_time + 1, False):
                            # Most threads will be waiting here.
                            self.etcd_client.watch(
                                self.master_key,
                                timeout=self.recovery_time)
                    except (etcd.EtcdWatchTimedOut, UrllibTimeoutError):
                        pass
                    except etcd.EtcdException:
                        eventlet.sleep(self.recovery_time)

    def extend_election(self, duration):
        """Assuming we are the master, attempt to extend our election time."""

        try:
            self.etcd_client.write(self.master_key,
                                   self.thread_id,
                                   prevValue=self.thread_id,
                                   ttl=duration)
            LOG.debug("Master thread %s extended election by %d secs",
                      self.thread_id, duration)
        except etcd.EtcdException:
            raise EtcdElectionLost()

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
        self.expected_keys = self.init_resync_start()
        self.refresh_all_data()

        # NB needs the lock to run safely.
        def short_keys():
            for f in self.etcd_data.keys():
                short_key = self.make_short_key(f)
                if short_key:
                    yield short_key

        with self.etcd_data_lock:
            self.init_resync_end(short_keys())

    def make_short_key(self, key):
        # TODO(ijw) .startswith would be more sensible
        m = re.match('^' + re.escape(self.watch_path) + '/(.*)$', key)
        if m:
            return m.group(1)
        else:
            return None

    def init_resync_start(self):
        """Overrideable function when the first resync starts

        Whatever is being driven by the etcd data, this is a good time
        to find out what state it's currently in.  It may be
        persisting data over a restart of this process watching etcd,
        so things that are no longer in etcd (for which we won't have
        seen deletes in the downtime) are now gone.  This is only
        needed initially; if a resync is required while we're running,
        we've tracked the etcd content and we know what has gone away.

        Returns: None for no cleanup, or a set of keys expected
        """
        return None

    def init_resync_end(self, short_keys):
        """Clean up stale data

        When we start up, we need to bring controlled elements
        into line with what etcd wants.  We've already gone
        through the keys in etcd that currently exist and made
        sure that the they are correctly configured, but we now
        need to remove any structures that correspond to items
        no longer in etcd.

        This may be overridden to add functionality.

        short_keys - an iterator for all the keys found in etcd
        """

        if self.expected_keys is None:
            # Resync has not been implemented for this
            # TODO(ijw): we should make it mandatory for resync
            # which means expected_resync_start will become
            # abstract.
            return

        stale_keys = set(self.expected_keys) - set(short_keys)
        for f in stale_keys:
            self.removed(f)

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
            except Exception:
                LOG.exception('%s: etcd threw exception',
                              self.name)
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
                rv = None
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
                            self.etcd_data.pop(rv.key, None)
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

        except (etcd.EtcdWatchTimedOut, UrllibTimeoutError):
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
    It does this by remembering what it's notified (via key_change) in
    the past, and avoiding any notification that amounts to 'this key has
    changed to the same value'.  However, when we have to do a full resync
    the ordering of key updates is not guaranteed.
    """

    def __init__(self, etcd_client, name, watch_path, election_path=None,
                 wait_until_elected=False, recovery_time=5,
                 data=None, heartbeat=60):
        self.implemented_state = {}
        self.watch_path = watch_path

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

    def key_change(self, action, key, value):
        """Called when a key changes from the known value

        This can be because it's added, changed, refreshed or deleted.
        This default implementation does not notify of a change at
        the root.  We assume only subkeys are interesting.
        """
        short_key = self.make_short_key(key)

        if short_key is not None:

            LOG.debug("Watcher %s got %s on shortkey %s",
                      self.name, action, short_key)

            if action == 'delete':
                self.removed(short_key)
            else:
                self.added(short_key, value)

    def removed(self, key):
        """Called when a key is deleted

        The watch path is removed, leaving only the subpath.
        """
        pass

    def added(self, key, value):
        """Called when a key is added, changed, updated...

        The watch path is removed, leaving only the subpath.
        """
        pass


class EtcdHelper(object):

    def __init__(self, client):
        self.etcd_client = client

    def clear_state(self, key_space):
        """Clear the keys in the key_space"""
        LOG.debug("Clearing key space: %s", key_space)
        try:
            rv = self.etcd_client.read(key_space)
            for child in rv.children:
                self.etcd_client.delete(child.key)
        except etcd.EtcdNotFile:
            # Can't delete directories - they're harmless anyway
            pass

    def ensure_dir(self, path):
        try:
            self.etcd_client.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass

    def remove_dir(self, path):
        try:
            self.etcd_client.delete(path, dir=True)
        except etcd.EtcdNotFile:
            # Thrown if the directory is not empty, which we error log
            LOG.error("Directory path:%s is not empty and cannot be deleted",
                      path)
        except etcd.EtcdKeyNotFound:
            # Already gone, so not a problem
            pass

# Base connection to etcd, using standard options.

_etcd_conn_opts = [
    cfg.StrOpt('etcd_host', default="127.0.0.1",
               help=_("Etcd host IP address(es) to connect etcd client."
                      "It takes two formats: single IP/host or a multiple "
                      "hosts list with this format: 'IP:Port,IP:Port'. "
                      "e.g: 192.168.1.1:2379,192.168.1.2:2379.  If port "
                      "is absent, etcd_port is used.")),
    cfg.IntOpt('etcd_port', default=4001,
               help=_("Etcd port to connect the etcd client.  This can "
                      "be overridden on a per-host basis if the multiple "
                      "host form of etcd_host is used.")),
    cfg.StrOpt('etcd_user', default=None,
               help=_("Username for etcd authentication")),
    cfg.StrOpt('etcd_pass', default=None, secret=True,
               help=_("Password for etcd authentication")),
    # TODO(ijw): make false default
    cfg.BoolOpt('etcd_insecure_explicit_disable_https', default=True,
                help=_("Use TLS to access etcd")),
    cfg.StrOpt('etcd_ca_cert', default=None,
               help=_("etcd CA certificate file path")),
]


def register_etcd_conn_opts(cfg, group):
    global _etcd_conn_opts
    cfg.register_opts(_etcd_conn_opts, group)


def list_opts():
    """Return config details for use with Oslo-config generator"""
    return _etcd_conn_opts


class EtcdClientFactory(object):
    def _parse_host(self, etc_host_elem, default_port):
        """Parse a single etcd host entry (which can be host or host/port)

        Returns a format suitable for the etcd client creation call.
        NB: the client call is documented to take one host, host/port
        tuple or a tuple of host/port tuples; in fact, it will take
        a bare host in the tuple form as well.
        """

        if not isinstance(etc_host_elem, str) or etc_host_elem == '':
            raise vpp_exceptions.InvalidEtcHostConfig()

        if ETC_PORT_HOST_DELIMITER in etc_host_elem:
            try:
                host, port = etc_host_elem.split(ETC_PORT_HOST_DELIMITER)
                port = int(port)
                etc_host = (host, port,)
            except ValueError:
                raise vpp_exceptions.InvalidEtcHostConfig()
        else:
            etc_host = (etc_host_elem, default_port)

        return etc_host

    def _parse_host_config(self, etc_host, default_port):
        """Parse etcd host config (host, host/port, or list of host/port)

        Returns a format suitable for the etcd client creation call.
        This always uses the list-of-hosts tuple format, even with a single
        host.
        """

        if not isinstance(etc_host, str):
            raise vpp_exceptions.InvalidEtcHostsConfig()

        if ETC_HOSTS_DELIMITER in etc_host:
            hosts = etc_host.split(ETC_HOSTS_DELIMITER)
        else:
            hosts = [etc_host]

        etc_hosts = ()
        for host in hosts:
            etc_hosts = etc_hosts + (self._parse_host(host, default_port),)

        return etc_hosts

    def __init__(self, conf_group):
        hostconf = self._parse_host_config(conf_group.etcd_host,
                                           conf_group.etcd_port)

        self.etcd_args = {
            'host': hostconf,
            'username': conf_group.etcd_user,
            'password': conf_group.etcd_pass,
            'allow_reconnect': True}

        if not conf_group.etcd_insecure_explicit_disable_https:
            if conf_group.etcd_ca_cert is None:
                raise vpp_exceptions.InvalidEtcdCAConfig()

            self.etcd_args['protocol'] = 'https'
            self.etcd_args['ca_cert'] = conf_group.etcd_ca_cert

        else:
            LOG.warning("etcd is not using HTTPS, insecure setting")

    def client(self):
        etcd_client = etcd.Client(**self.etcd_args)

        return etcd_client
