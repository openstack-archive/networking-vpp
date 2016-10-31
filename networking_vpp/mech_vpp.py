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
import eventlet.event
import json
from oslo_config import cfg
from oslo_log import log as logging
import re
import six
import time
import traceback

import backward_compatibility as bc_attr

from networking_vpp import config_opts
from networking_vpp.db import db
from neutron.common import constants as n_const
from neutron import context as n_context
from neutron.db import api as neutron_db_api
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api

from urllib3.exceptions import TimeoutError

eventlet.monkey_patch()

LOG = logging.getLogger(__name__)


class VPPMechanismDriver(api.MechanismDriver):
    supported_vnic_types = [portbindings.VNIC_NORMAL]
    allowed_network_types = [p_constants.TYPE_FLAT,
                             p_constants.TYPE_VLAN,
                             p_constants.TYPE_VXLAN]
    MECH_NAME = 'vpp'

    vif_details = {}

    def initialize(self):
        cfg.CONF.register_opts(config_opts.vpp_opts, "ml2_vpp")
        self.communicator = EtcdAgentCommunicator()
        self.keepalive = FeatureKeepAlive()
        self.ports = FeaturePortBinding()
        self.physnets = FeaturePhysnets()
        self.communicator.register_feature(self.keepalive)
        self.communicator.register_feature(self.ports)
        self.communicator.register_feature(self.physnets)

    def get_vif_type(self, port_context):
        """Determine the type of the vif to be bound from port context"""

        # Default vif type
        vif_type = 'vhostuser'

        # We have to explicitly avoid binding agent ports - DHCP,
        # L3 etc. - as vhostuser. The interface code below takes
        # care of those.

        owner = port_context.current['device_owner']
        for f in bc_attr.DEVICE_OWNER_PREFIXES:
            if owner.startswith(f):
                vif_type = 'plugtap'
        LOG.debug("ML2_VPP: vif_type to be bound is: %s", vif_type)
        return vif_type

    def bind_port(self, port_context):
        """Attempt to bind a port.

        :param port_context: PortContext instance describing the port

        This method is called outside any transaction to attempt to
        establish a port binding using this mechanism driver. Bindings
        may be created at each of multiple levels of a hierarchical
        network, and are established from the top level downward. At
        each level, the mechanism driver determines whether it can
        bind to any of the network segments in the
        port_context.segments_to_bind property, based on the value of the
        port_context.host property, any relevant port or network
        attributes, and its own knowledge of the network topology. At
        the top level, port_context.segments_to_bind contains the static
        segments of the port's network. At each lower level of
        binding, it contains static or dynamic segments supplied by
        the driver that bound at the level above. If the driver is
        able to complete the binding of the port to any segment in
        port_context.segments_to_bind, it must call port_context.set_binding
        with the binding details. If it can partially bind the port,
        it must call port_context.continue_binding with the network
        segments to be used to bind at the next lower level.

        If the binding results are committed after bind_port returns,
        they will be seen by all mechanism drivers as
        update_port_precommit and update_port_postcommit calls. But if
        some other thread or process concurrently binds or updates the
        port, these binding results will not be committed, and
        update_port_precommit and update_port_postcommit will not be
        called on the mechanism drivers with these results. Because
        binding results can be discarded rather than committed,
        drivers should avoid making persistent state changes in
        bind_port, or else must ensure that such state changes are
        eventually cleaned up.

        Implementing this method explicitly declares the mechanism
        driver as having the intention to bind ports. This is inspected
        by the QoS service to identify the available QoS rules you
        can use with ports.
        """
        LOG.debug("ML2_VPP: Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': port_context.current['id'],
                   'network': port_context.network.current['id']})
        vnic_type = port_context.current.get(portbindings.VNIC_TYPE,
                                             portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("ML2_VPP: Refusing to bind due to unsupported "
                      "vnic_type: %s",
                      vnic_type)
            return

        for segment in port_context.segments_to_bind:
            if self.check_segment(segment, port_context.host):
                vif_details = dict(self.vif_details)
                # TODO(ijw) should be in a library that the agent uses
                vif_type = self.get_vif_type(port_context)
                if vif_type == 'vhostuser':
                    vif_details['vhostuser_socket'] = \
                        '/tmp/%s' % port_context.current['id']
                    vif_details['vhostuser_mode'] = 'server'
                LOG.debug('ML2_VPP: Setting details: %s', vif_details)
                port_context.set_binding(segment[api.ID],
                                         vif_type,
                                         vif_details)
                LOG.debug("ML2_VPP: Bound using segment: %s", segment)
                return

    def check_segment(self, segment, host):
        """Check if segment can be bound.

        :param segment: segment dictionary describing segment to bind
        :param host: host on which the segment must be bound to a port
        :returns: True iff segment can be bound for host

        """

        # TODO(ijw): naive - doesn't check host, or configured
        # physnets on the host.  Should work out if the binding
        # can't be achieved before accepting it

        network_type = segment[api.NETWORK_TYPE]
        if network_type not in self.allowed_network_types:
            LOG.debug(
                'ML2_VPP: Network %(network_id)s is %(network_type)s, '
                'but this driver only supports types '
                '%(allowed_network_types)s. '
                'The type must be supported  if binding is to succeed.',
                {'network_id': segment['id'],
                 'network_type': network_type,
                 'allowed_network_types':
                 ', '.join(self.allowed_network_types)}
            )
            return False

        if network_type in [p_constants.TYPE_FLAT, p_constants.TYPE_VLAN]:
            physnet = segment[api.PHYSICAL_NETWORK]
            if not self.physnet_known(host, physnet):
                LOG.debug(
                    'ML2_VPP: Network %(network_id)s is on physical '
                    'network %(physnet)s, but the physical network '
                    'is not one the host %(host)s has attached.',
                    {'network_id': segment['id'],
                     'physnet': physnet,
                     'host': host}
                )
                return False

        return True

    def physnet_known(self, host, physnet):
        return (host, physnet) in self.physnets.read()

    def check_vlan_transparency(self, port_context):
        """Check if the network supports vlan transparency.

        :param port_context: NetworkContext instance describing the network.

        In general we do not support VLAN transparency (yet).
        """
        return False

    def update_port_precommit(self, port_context):
        """Work to do, during DB commit, when updating a port

        If we are partially responsible for binding this port, we will
        have to tell our agents they have work to do.  This is an
        operation within a distributed system and can therefore take
        time to complete, or potentially even fail.  Instead, we log
        the requirement to a journal.
        """
        # TODO(ijw): optimisation: the update port may leave the
        # binding state the same as before if someone updated
        # something other than the binding on the port, but this
        # way we always send it out and it's the far end's job to
        # ignore it.  Doing less work is nevertheless good, so we
        # should in future avoid the send.

        if port_context.binding_levels is not None:
            current_bind = port_context.binding_levels[-1]
            if port_context.original_binding_levels is None:
                prev_bind = None
            else:
                prev_bind = port_context.original_binding_levels[-1]

            binding_type = self.get_vif_type(port_context)

            if (current_bind is not None and
               current_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                # then send the bind out (may equally be an update on a bound
                # port)
                self.ports.bind(port_context._plugin_context.session,
                                port_context.current,
                                current_bind[api.BOUND_SEGMENT],
                                port_context.host,
                                binding_type)
            elif (prev_bind is not None and
                  prev_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                # If we were the last binder of this port but are no longer
                self.ports.unbind(port_context._plugin_context.session,
                                  port_context.current,
                                  port_context.original_host)

    def update_port_postcommit(self, port_context):
        """Work to do, post-DB commit, when updating a port

        After accepting an update_port, determine if we logged any
        work to do on the networking devices, and - if so - kick the
        update thread that tells our minions.

        """
        # TODO(ijw): optimisation: the update port may leave the
        # binding state the same as before if someone updated
        # something other than the binding on the port, but this
        # way we always send it out and it's the far end's job to
        # ignore it.  Doing less work is nevertheless good, so we
        # should in future avoid the send.

        if port_context.binding_levels is not None:
            current_bind = port_context.binding_levels[-1]
            if port_context.original_binding_levels is None:
                prev_bind = None
            else:
                prev_bind = port_context.original_binding_levels[-1]

            if (current_bind is not None and
               current_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                self.communicator.kick()
            elif (prev_bind is not None and
                  prev_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                self.communicator.kick()

    def delete_port_precommit(self, port_context):
        port = port_context.current
        host = port_context.host
        LOG.debug('ML2_VPP: delete_port_postcommit, port is %s' % str(port))
        self.ports.unbind(port_context._plugin_context.session,
                          port, host)

    def delete_port_postcommit(self, port_context):
        self.communicator.kick()


@six.add_metaclass(ABCMeta)
class Feature(object):
    path = ''

    def __init__(self):
        # this var will be set when register_feature
        # method will be called
        self.communicator = None
        pass

    @abstractmethod
    def state_create(self, host, key, value):
        """Feature for host was created.

        Typically called when an agent has done
        its job, such as creating a port.
        """
        pass

    @abstractmethod
    def state_set(self, host, key, value):
        pass

    @abstractmethod
    def state_delete(self, host, key, value):
        """Feature for host was deleted.

        In this case, the value will always be 'None'.
        Yet, this parameter is mandatory as the call is generated.
        """
        pass

    @abstractmethod
    def resync(self):
        """Resync with etcd state.

        We should clean our internal cached values
        """
        pass


class FeatureKeepAlive(Feature):
    path = 'alive'

    def state_create(self, host, key, value):
        LOG.info('host %s is new and alive' % host)

    def state_set(self, host, key, value):
        LOG.info('host %s is alive' % host)

    def state_delete(self, host, key, value):
        LOG.info('host %s has died' % host)

    def resync(self):
        pass


class FeaturePhysnets(Feature):
    path = 'physnets'

    def __init__(self):
        self.physnets = set()

    def state_create(self, host, key, value):
        LOG.info('host "%s" has new physnet: "%s"' % (host, key))
        self.physnets.add((host, key))

    def state_set(self, host, key, value):
        LOG.info('host "%s" has update physnet: "%s"' % (host, key))
        self.physnets.add((host, key))

    def state_delete(self, host, key, value):
        LOG.info('host "%s" has no more physnet: "%s"' % (host, key))
        self.physnets.remove((host, key))

    def resync(self):
        self.physnets = set()

    def read(self):
        physical_networks = set()
        etcd_phynets = self.communicator.etcd_client.read(LEADIN,
                                                          recursive=True)
        for rv in etcd_phynets.children:
            # Find all known physnets
            m = re.match(self.communicator.state_key_space +
                         '/([^/]+)/physnets/([^/]+)$', rv.key)
            if m:
                host = m.group(1)
                net = m.group(2)
                physical_networks.add((host, net))

        return physical_networks


class FeaturePortBinding(Feature):
    path = 'ports'

    def __init__(self):
        self.recursive = False

    def state_create(self, host, key, value):
        LOG.error('FeaturePortBinding created %s %s' % (host, key))
        self.notify_bound(key, host)

    def state_set(self, host, key, value):
        LOG.error('FeaturePortBinding seted %s %s' % (host, key))
        self.notify_bound(key, host)
        pass

    def state_delete(self, host, key, value):
        # Nove doesn't nuch care when ports go away
        pass

    def resync(self):
        self.recursive = False
        pass

    def _port_path(self, host, port):
        return (self.communicator.port_key_space +
                "/" + host + "/ports/" + port['id'])

    def bind(self, session, port, segment, host, binding_type):
        # NB segmentation_id is not optional in the wireline protocol,
        # we just pass 0 for unsegmented network types
        data = {
            'mac_address': port['mac_address'],
            'mtu': 1500,  # not this, but what?: port['mtu'],
            'physnet': segment[api.PHYSICAL_NETWORK],
            'network_type': segment[api.NETWORK_TYPE],
            'segmentation_id': segment.get(api.SEGMENTATION_ID, 0),
            'binding_type': binding_type,
        }
        LOG.debug("ML2_VPP: Queueing bind request for port:%s, "
                  "segment:%s, host:%s, type:%s",
                  port, data['segmentation_id'],
                  host, data['binding_type'])

        db.journal_write(session, self._port_path(host, port), data)
        self.communicator.kick()

    def unbind(self, session, port, host):
        db.journal_write(session, self._port_path(host, port), None)
        self.communicator.kick()

    def notify_bound(self, port_id, host):
        """Tell things that the port is truly bound.

        You want to call this when you're certain that the VPP
        on the far end has definitely bound the port, and has
        dropped a vhost-user socket where it can be found.

        You want to do this then specifically because libvirt
        will hang, because qemu ignores its monitor port,
        when qemu is waiting for a partner to connect with on
        its vhost-user interfaces.  It can't start the VM - that
        requires information from its partner it can't guess at -
        but it shouldn't hang the monitor - nevertheless...

        In the case your comms protocol is sucky, call it at
        the end of a bind() and everything will probably be
        fine.  Probably.
        """

        context = n_context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        # Bodge TODO(ijw)
        if self.recursive:
            # This happens right now because when we update the port
            # status, we update the port and the update notification
            # comes through to here.
            # TODO(ijw) wants a more permanent fix, because this only
            # happens due to the threading model.  We should be
            # spotting relevant changes in postcommit.
            LOG.warning('ML2_VPP: recursion check hit on activating port')
        else:
            self.recursive = True
            plugin.update_port_status(context, port_id,
                                      n_const.PORT_STATUS_ACTIVE,
                                      host=host)
            self.recursive = False


# If no-one from Neutron talks to us in this long, get paranoid and check the
# database for work.  We might have missed the kick (or another
# process may have added work and then died before processing it).
PARANOIA_TIME = 50              # TODO(ijw): make configurable?
# Our prefix for etcd keys, in case others are using etcd.
LEADIN = '/networking-vpp'      # TODO(ijw): make configurable?


class EtcdAgentCommunicator(object):
    """Comms unit for etcd

    This will talk to etcd and tell it what is going on
    with the Neutron database.  etcd can be run as a
    cluster and so shouldn't die, but can be unreachable,
    so this class's job is to ensure that all updates are
    forwarded to etcd in order even when things are not
    quite going as planned.

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
        LOG.debug("Using etcd host:%s port:%s user:%s password:***" %
                  (cfg.CONF.ml2_vpp.etcd_host,
                   cfg.CONF.ml2_vpp.etcd_port,
                   cfg.CONF.ml2_vpp.etcd_user,))
        self.etcd_client = etcd.Client(host=cfg.CONF.ml2_vpp.etcd_host,
                                       port=cfg.CONF.ml2_vpp.etcd_port,
                                       username=cfg.CONF.ml2_vpp.etcd_user,
                                       password=cfg.CONF.ml2_vpp.etcd_pass,
                                       allow_reconnect=True)
        self.features = {}
        # We need certain directories to exist
        self.state_key_space = LEADIN + '/state'
        self.port_key_space = LEADIN + '/nodes'
        self.do_etcd_mkdir(self.state_key_space)
        self.do_etcd_mkdir(self.port_key_space)

        # TODO(ijw): .../state/<host> lists all known hosts, and they
        # heartbeat when they're functioning

        self.db_q_ev = eventlet.event.Event()

        self.return_thread = eventlet.spawn(self._return_worker)
        self.forward_thread = eventlet.spawn(self._forward_worker)

    def register_feature(self, feature):
        if feature.path in self.features.keys():
            raise Exception('Feature "%s" can not be registered twice'
                            % feature.path)
        feature.communicator = self
        self.features[feature.path] = feature

    ######################################################################
    # These functions use a DB journal to log messages before
    # they're put into etcd, as that can take time and may not always
    # succeed (so is a bad candidate for calling within or after a
    # transaction).

    kick_count = 0

    def kick(self):
        if not self.db_q_ev.ready():
            self.kick_count = self.kick_count + 1
            try:
                self.db_q_ev.send(self.kick_count)
            except AssertionError:
                # We send even on triggered events (which is fine: it's a
                # wakeup signal and harmless to send repeatedly), but
                # we need to ignore the error
                pass

    ######################################################################
    # The post-journal part of the work that clears out the table and
    # updates etcd.

    def do_etcd_update(self, k, v):
        try:
            # not needed? - do_etcd_mkdir('/'.join(k.split('/')[:-1]))
            if v is None:
                LOG.debug('deleting key %s' % k)
                try:
                    self.etcd_client.delete(k)
                except etcd.EtcdKeyNotFound:
                    # The key may have already been deleted
                    # no problem here
                    pass
            else:
                LOG.debug('writing key %s' % k)
                self.etcd_client.write(k, json.dumps(v))
            return True
        except Exception:       # TODO(ijw) select your exceptions
            return False

    def do_etcd_mkdir(self, path):
        try:
            self.etcd_client.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass

    def _forward_worker(self):
        LOG.debug('forward worker begun')

        session = neutron_db_api.get_session()
        while True:
            try:
                def work(k, v):
                    LOG.debug('forward worker updating etcd key %s' % k)
                    if self.do_etcd_update(k, v):
                        return True
                    else:
                        # something went bad; breathe, in case we end
                        # up in a tight loop
                        time.sleep(1)
                        return False

                LOG.debug('forward worker reading journal')
                while db.journal_read(session, work):
                    pass
                LOG.debug('forward worker has emptied journal')

                # work queue is now empty.
                LOG.debug("ML2_VPP(%s): worker thread pausing"
                          % self.__class__.__name__)
                # Wait to be kicked, or (in case of emergency) run every
                # few seconds in case another thread or process dumped
                # work and failed to process it
                try:
                    with eventlet.Timeout(PARANOIA_TIME):
                        # Wait for kick
                        dummy = self.db_q_ev.wait()
                        # Clear the event - we will now process till
                        # we've run out of things in the backlog
                        # so any trigger lost in this gap is harmless
                        self.db_q_ev.reset()
                        LOG.debug("ML2_VPP(%s): worker thread kicked: %s"
                                  % (self.__class__.__name__, str(dummy)))
                except eventlet.Timeout:
                    LOG.debug("ML2_VPP(%s): worker thread suspicious of "
                              "a long pause"
                              % self.__class__.__name__)
                    pass
                LOG.debug("ML2_VPP(%s): worker thread active"
                          % self.__class__.__name__)
            except Exception as e:
                # TODO(ijw): log exception properly
                LOG.error("problems in forward worker: %s", e)
                LOG.error(traceback.format_exc())
                # never quit
                pass

    ######################################################################

    def _return_worker(self):
        """The thread that manages data returned from agents via etcd."""

        # TODO(ijw): this should begin by syncing state, particularly
        # of agents but also of any notifications for which we missed
        # the watch event.

        # TODO(ijw): agents
        # TODO(ijw): notifications

        tick = None
        while True:

            try:
                LOG.debug("ML2_VPP(%s): return worker pausing"
                          % self.__class__.__name__)
                try:
                    if tick is None:
                        raise etcd.EtcdEventIndexCleared()

                    rv = self.etcd_client.watch(self.state_key_space,
                                                recursive=True,
                                                index=tick)
                    vals = [rv]

                    next_tick = rv.modifiedIndex + 1

                except etcd.EtcdEventIndexCleared:
                    LOG.debug("Received etcd event index cleared. "
                              "Recovering etcd watch index")
                    rv = self.etcd_client.read(self.state_key_space,
                                               recursive=True)
                    vals = rv.children
                    for feature in self.features.values():
                        feature.resync()

                    next_tick = rv.etcd_index + 1

                    LOG.debug("Etcd watch index recovered at index:%s"
                              % next_tick)

                for kv in vals:
                    LOG.debug("ML2_VPP(%s): feature return worker active"
                              % self.__class__.__name__)

                    m = re.match(self.state_key_space +
                                 '/([^/]+)/([^/]+)(/?)([^/]*)$',
                                 kv.key)
                    if m:
                        host = m.group(1)
                        feature = m.group(2)
                        if len(m.groups()) > 3:
                            key = m.group(4)
                        else:
                            key = None

                        if feature in self.features.keys():
                            # Dynamically build method name
                            # and call appropriate feature
                            # eg: port->state_created
                            if kv.action is None:
                                kv.action = 'create'
                            method = 'state_' + str(kv.action)
                            feature_instance = self.features[feature]
                            func = getattr(feature_instance, method)
                            func(host, key, kv.value)

                        else:
                            LOG.warn('Unexpected key change in '
                                     'etcd port feedback: %s' % kv.key)

                # Update the tick only when all the above completes so that
                # exceptions don't cause the count to skip before the data
                # is processed
                tick = next_tick

            except (etcd.EtcdWatchTimedOut, TimeoutError):
                # this is normal
                pass
            except Exception as e:
                LOG.warning('etcd threw exception %s'
                            % traceback.format_exc(e))
                # In case of a dead etcd causing continuous
                # exceptions, the pause here avoids eating all the
                # CPU
                time.sleep(2)
