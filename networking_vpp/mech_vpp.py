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

from abc import ABCMeta, abstractmethod
import etcd
import eventlet
import eventlet.queue
import json
from oslo_config import cfg
from oslo_log import log as logging
import re
import requests
import time
import traceback

from neutron.common import constants as n_const
from neutron import context as n_context
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api
from neutron_lib import constants as nl_const

eventlet.monkey_patch()

LOG = logging.getLogger(__name__)

vpp_opts = [
    cfg.StrOpt('agents',
               help=_("Name=HTTP URL mapping list of agents on compute "
                      "nodes.")),
]

cfg.CONF.register_opts(vpp_opts, "ml2_vpp")


class VPPMechanismDriver(api.MechanismDriver):
    supported_vnic_types = [portbindings.VNIC_NORMAL]
    allowed_network_types = [p_constants.TYPE_FLAT,
                             p_constants.TYPE_VLAN,
                             p_constants.TYPE_VXLAN]
    MECH_NAME = 'vpp'

    vif_details = {}

    def initialize(self):
        self.communicator = EtcdAgentCommunicator()

    def get_vif_type(self, port_context):
        """Determine the type of the vif to be bound from port context"""

        # Default vif type
        vif_type = 'vhostuser'

        # We have to explicitly avoid binding agent ports - DHCP,
        # L3 etc. - as vhostuser. The interface code below takes
        # care of those.

        owner = port_context.current['device_owner']
        for f in nl_const.DEVICE_OWNER_PREFIXES:
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
                    vif_details['vhostuser_mode'] = 'client'
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
        return (host, physnet) in self.communicator.physical_networks

    def check_vlan_transparency(self, port_context):
        """Check if the network supports vlan transparency.

        :param port_context: NetworkContext instance describing the network.

        In general we do not support VLAN transparency (yet).
        """
        return False

    def update_port_postcommit(self, port_context):
        """Work to do, post-DB commit, when updating a port

        After accepting an update_port, determine if we have any work to do
        on the network devices.
        """
        # TODO(ijw): optimisation: the update port may leave the
        # binding state the same as before if someone updated
        # something other than the binding on the port, but this
        # way we always send it out and it's the far end's job to
        # ignore it.  Doing less work is nevertheless good, so we
        # should in future avoid the send.

        LOG.debug('ML2_VPP: update_port_postcommit, port is %s'
                  % str(port_context.current))

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
                LOG.debug("ML2-VPP: Sending bind request to agent "
                          "communicator for port %(port) segment %(segment)s, "
                          "host %(host)s, binding_type %(binding_type)s",
                          {
                              'port': port_context.current,
                              'segment': current_bind[api.BOUND_SEGMENT],
                              'host': port_context.host,
                              'binding_type': binding_type
                          })
                self.communicator.bind(port_context.current,
                                       current_bind[api.BOUND_SEGMENT],
                                       port_context.host,
                                       binding_type)
            elif (prev_bind is not None and
                  prev_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                # If we were the last binder of this port but are no longer
                LOG.debug("ML2_VPP: Sending unbind request to agent "
                          "communicator for port %(port)s on host %(host)s",
                          {
                              'port': port_context.current,
                              'host': port_context.original_host,
                          })
                self.communicator.unbind(port_context.current,
                                         port_context.original_host)


class AgentCommunicator(object):
    __metaclass__ = ABCMeta

    def __init__(self):
       self.recursive = False

    @abstractmethod
    def bind(self, port, segment, host, binding_type):
        pass


    @abstractmethod
    def unbind(self, port, host):
        pass

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


class ThreadedAgentCommunicator(AgentCommunicator):
    __metaclass__ = ABCMeta

    def __init__(self):
        super(ThreadedAgentCommunicator, self).__init__()
        self.queue = eventlet.queue.Queue()
        self.sync_thread = eventlet.spawn(self._worker)

    def _worker(self):
        while True:
            LOG.debug("ML2_VPP(%s): worker thread pausing" % self.__class__.__name__)
            msg = self.queue.get()
            LOG.debug("ML2_VPP(%s): worker thread active" % self.__class__.__name__)
            op = msg[0]
            args = msg[1:]
            if op == 'bind':
                self.send_bind(*args)
            elif op == 'unbind':
                self.send_unbind(*args)
            else:
                LOG.error('ML2_VPP: unknown queue op %s' % str(op))

    def bind(self, port, segment, host, binding_type):
        """Queue up a bind message for sending.

        This is called in the sequence of a REST call and should take
        as little time as possible.
        """

        LOG.debug("ML2_VPP: Queueing bind request for port:%(port)s, "
                  "segment:%(segment)s on host:%(host)s, type:%(type)s",
                  {
                      'port': port,
                      'segment': segment,
                      'host': host,
                      'type': binding_type
                  })
        self.queue.put(['bind', port, segment, host, binding_type])

    def unbind(self, port, host):
        """Queue up an unbind message for sending.

        This is called in the sequence of a REST call and should take
        as little time as possible.
        """

        LOG.debug("ML2_VPP: Queueing unbind request for port:%(port)s,"
                  "on host:%(host)s,",
                  {
                      'port': port,
                      'host': host
                  })
         self.queue.put(['unbind', port, host])

    @abstractmethod
    def send_bind(self, port, segment, host, binding_type):
       pass

    @abstractmethod
    def send_unbind(self, port, host):
       pass

class CompoundAgentCommunicator(AgentCommunicator):
    # A quick test hack, don't take this too seriously
    def __init__(self):
       super(CompoundAgentCommunicator, self).__init__()
       self.sub = [EtcdAgentCommunicator(), SimpleAgentCommunicator()]

    def bind(self, *args):
       for f in self.sub:
            f.bind(*args)

    def unbind(seelf, *args):
       for f in self.sub:
            f.bind(*args)

LEADIN = '/networking-vpp'  # TODO: make configurable?
class EtcdAgentCommunicator(ThreadedAgentCommunicator):
    """Comms unit for etcd (in progress at the moment)

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
        super(EtcdAgentCommunicator, self).__init__()

        # if cfg.CONF.ml2_vpp.etcd is None:
        #     LOG.error('ML2_VPP: needs etcd endpoints to talk to')

        self.physical_networks = set()

        self.etcd = etcd.Client()  # TODO(ijw): give this args

        # We need certain directories to exist
        self.mkdir(LEADIN + '/state')
        self.mkdir(LEADIN + '/nodes')

        self.return_thread = eventlet.spawn(self._return_worker)

    def port_path(self, host, port):
        return LEADIN + "/nodes/" + host + "/ports/" + port['id']

    def send_bind(self, port, segment, host, binding_type):
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

       self.etcd.write(self.port_path(host, port),
                       json.dumps(data))

    def send_unbind(self, port, host):
        self.etcd.delete(self.port_path(host, port))

    def mkdir(self, path):
        try:
            self.etcd.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass

     def _return_worker(self):
          # TODO this should begin by syncing state, particularly of agents but also of any expected, unreceived notifications


          for rv in self.etcd.read(LEADIN, recursive=True).children:
              # Find all known physnets
              m = re.match(LEADIN + '/state/([^/]+)/physnets/([^/]+)$', rv.key)

              if m:
              host = m.group(1)
              net = m.group(2)

              self.physical_networks.add((host, net))

        tick = None
          TIMEOUT = 60  # In theory, to prevent long lived stale TCP connections
        while True:
              try:
               LOG.debug("ML2_VPP(%s): return thread pausing" % self.__class__.__name__)
               rv = self.etcd.watch(LEADIN + "/state", recursive=True,
                                    index=tick)
               LOG.debug("ML2_VPP(%s): return thread active" % self.__class__.__name__)
                tick = rv.modifiedIndex+1

               # Matches a port key, gets host and uuid
               m = re.match(LEADIN + '/state/([^/]+)/ports/([^/]+)$', rv.key)

               if m:
                   host = m.group(1)
                   port = m.group(2)

                   if rv.action == 'delete':
                       # TODO(ijw) there are probably more events to notify
                       pass
                   else:
                       self.notify_bound(port, host)
               else:
                   # Matches a port key, gets host and uuid
                    m = re.match(LEADIN + '/state/([^/]+)/alive$', rv.key)

                   if m:
                       host = m.group(1)

                       LOG.info('host %s is alive' % host)
                   else:
                       m = re.match(LEADIN + '/state/([^/]+)/physnets/([^/]+)$', rv.key)

                       if m:
                           host = m.group(1)
                           net = m.group(2)
                           if rv.action == 'delete':
                               self.physical_networks.remove((host, net))
                          else:
                               self.physical_networks.add((host, net))
                       else:
                           LOG.warn('Unexpected key change in etcd port feedback')

           except etcd.EtcdWatchTimedOut:
               # this is normal
               pass
           except Exception, e:
               LOG.warning('etcd threw exception %s' % traceback.format_exc(e))
               time.sleep(2)
               # TODO(ijw): Should be specific to etcd faults? should have sensible behaviour
               # Don't just kill the thread...
