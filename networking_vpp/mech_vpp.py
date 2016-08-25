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

import eventlet.queue
from oslo_config import cfg
from oslo_log import log as logging
import requests
import threading
import socket
from neutron.common import constants as n_const
from neutron import context as n_context
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api
from neutron_lib import constants as nl_const

LOG = logging.getLogger(__name__)

vpp_opts = [
    cfg.StrOpt('agents',
               help=_("HTTP URLs of agents on compute nodes.")),
]

cfg.CONF.register_opts(vpp_opts, "ml2_vpp")


class VPPMechanismDriver(api.MechanismDriver):
    supported_vnic_types = [portbindings.VNIC_NORMAL]
    allowed_network_types = [p_constants.TYPE_FLAT,p_constants.TYPE_VLAN,p_constants.TYPE_VXLAN]
    MECH_NAME = 'vpp'
    # TODO(ijw) should be pulled from a constants file
    #vif_type = 'vhostuser'
    vif_details = {}

    # TODO(ijw): we have no agent registration because we're not using
    # Neutron style agents, so at the moment we make up one physical net
    # that all 'agents' are assumed to know.
    physical_networks = ['physnet']

    def initialize(self):
        self.communicator = AgentCommunicator()

    def get_vif_type(self, port_context):
        """
        Determine the type of the vif to be bound from port context
        """
        #Default vif type
        vif_type = 'vhostuser'
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
            LOG.debug("ML2_VPP: Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        for segment in port_context.segments_to_bind:
            if self.check_segment(segment, port_context.host):
                vif_details = dict(self.vif_details)
                # TODO(ijw) should be in a library that the agent uses
                if self.get_vif_type(port_context) == 'vhostuser':
                    vif_details['vhostuser_socket'] = \
                        '/tmp/%s' % port_context.current['id']
                    vif_details['vhostuser_mode'] = 'client'
                LOG.debug('ML2_VPP: Setting details: %s', vif_details)
                port_context.set_binding(segment[api.ID],
                                         self.get_vif_type(port_context),
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
                'ML2_VPP: Network %(network_id)s is %(network_type)s, but this driver '
                'only supports types %(allowed_network_types)s.  The type '
                'must be supported  if binding is to succeed.',
                {'network_id': segment['id'],
                 'network_type': network_type,
                 'allowed_network_types':
                 ', '.join(self.allowed_network_types)}
            )
            return False

        if network_type in [p_constants.TYPE_FLAT, p_constants.TYPE_VLAN]:
            physnet = segment[api.PHYSICAL_NETWORK]
            if not self.physnet_known(physnet, network_type):
                LOG.debug(
                    'ML2_VPP: Network %(network_id)s is connected to physical '
                    'network %(physnet)s, but the physical network '
                    'is not one this mechdriver knows.  The physical network '
                    'must be known if binding is to succeed.',
                    {'network_id': segment['id'],
                     'physnet': physnet}
                )
                return False

        return True

    def physnet_known(self, physnet, network_type):
        """
        Support binding to arbitrary flat networks and a single Vlan physical network
        """
        if network_type == 'flat':
            return True
        else:
            return physnet in self.physical_networks

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

        LOG.debug('ML2_VPP: update_port_postcommit, port is %s' % str(port_context.current))

        if port_context.binding_levels is not None:
            current_bind = port_context.binding_levels[-1]
            if port_context.original_binding_levels is None:
                prev_bind = None
            else:
                prev_bind = port_context.original_binding_levels[-1]

            # We have to explicitly avoid binding agent ports - DHCP,
            # L3 etc. - as vhostuser. The interface code below takes
            # care of those.

            #bind_type = 'vhostuser'

            #owner = port_context.current['device_owner']

            # Neutron really ought to tell us what port type it thinks
            # is sensible, but it leaves us to make an educated guess.
            #for f in nl_const.DEVICE_OWNER_PREFIXES:
            #   if owner.startswith(f):
            #        bind_type = 'plugtap'
            bind_type = self.get_vif_type(port_context)

            LOG.error('binding to with type %s' % bind_type)

            if (current_bind is not None and
               current_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                # then send the bind out (may equally be an update on a bound
                # port)
                LOG.debug("ML2-VPP: Sending bind request to agent communicator for port %(port)s"
                          "segment %(segment)s, host %(host)s, type %(bind_type)s",
                          {
                          'port': port_context.current,
                          'segment': current_bind[api.BOUND_SEGMENT],
                          'host': port_context.host,
                          'bind_type': bind_type
                          }
                         )
                self.communicator.bind(port_context.current,
                                       current_bind[api.BOUND_SEGMENT],
                                       port_context.host,
                                       bind_type)
            elif (prev_bind is not None and
                  prev_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                # If we were the last binder of this port but are no longer
                LOG.debug("ML2_VPP: Sending unbind request to agent communicator for port %(port)s"
                          "on host %(host)s",
                          {
                          'port': port_context.current,
                          'host': port_context.original_host,
                          }
                         )
                self.communicator.unbind(port_context.current,
                                         port_context.original_host)


class AgentCommunicator(object):
    def __init__(self):
        if cfg.CONF.ml2_vpp.agents is None:
            LOG.error('ML2_VPP: needs agents configured right now')
        self.agents = cfg.CONF.ml2_vpp.agents.split(',')
        LOG.debug("ML2_VPP: Configured agents are: %s " % str(self.agents))
        self.recursive = False
        self.queue = eventlet.queue.Queue()
        self.sync_thread = threading.Thread(
            name='vpp-sync',
            target=self._worker)
        self.sync_thread.start()

    def _worker(self):
        while True:
            msg = self.queue.get()
            op = msg[0]
            args = msg[1:]
            if op == 'bind':
                self.send_bind(*args)
            elif op == 'unbind':
                self.send_unbind(*args)
            else:
                LOG.error('ML2_VPP: unknown queue op %s' % str(op))

    def bind(self, port, segment, host, bind_type):
        """Queue up a bind message for sending.

        This is called in the sequence of a REST call and should take
        as little time as possible.
        """
        LOG.debug("ML2_VPP: Communicating bind request to agent for port:%(port)s, segment:%(segment)s"
                  "on host:%(host)s, type:%(type)s",
                  {
                  'port': port, 'segment': segment,
                  'host': host, 'type': type
                  } )
        #self.queue.put(['bind', port, segment, host, type])
        ##TODO(njoy) Implement an RPC call with request response to confirm that binding/unbinding has
        ##been successful at the agent
        self.send_bind(port, segment, host, type)

    def unbind(self, port, host):
        """Queue up an unbind message for sending.

        This is called in the sequence of a REST call and should take
        as little time as possible.
        """
        LOG.debug("ML2_VPP: Communicating unbind request to agent for port:%(port)s,"
                  "on host:%(host)s,",
                  {
                  'port': port,
                  'host': host
                  } )
         #self.queue.put(['unbind', port, host])
         self.send_unbind(port, host)

    def send_bind(self, port, segment, host, type):
        data = {
            'host': host,
            'mac_address': port['mac_address'],
            'mtu': 1500,  # not this, but what?: port['mtu'],
            'network_type': segment[api.NETWORK_TYPE],
            'segmentation_id': segment[api.SEGMENTATION_ID]
                                   if segment[api.SEGMENTATION_ID] is not None else 0,
            'bind_type': type
        }
        self._unicast_msg('ports/%s/bind' % port['id'], data)

        # This should only be sent when we're certain that the port
        # is bound. If this is in a bg thread, it should be sent there,
        # and it should only go when we have confirmed that the far end
        # has done its work.  The VM will start when it's called and
        # will wait until then.  For us this is useful beyond the usual
        # reasons of deplying the VM start until DHCP can be reached,
        # because we know the server socket is in place for the port.

        context = n_context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()

        self.notify_bound(self, port, host)

    def notify_bound(self, port, host)
        # Bodge TODO(ijw)
        if self.recursive:
            # This happens right now because when we update the port
            # status, we update the port and the update notification
            # comes through to here.
            # TODO(ijw) wants a more permanent fix, because this only
            # happens due to the threading model.  We should be
            # spotting relevant changes in postcommit.
            LOG.warning('ML2_VPP: Your recursion check hit on activating port')
        else:
            self.recursive = True
            plugin.update_port_status(context, port['id'],
                                      n_const.PORT_STATUS_ACTIVE,
                                      host=host)
            self.recursive = False

    def send_unbind(self, port, host):
        data = {'host': host}
        self._unicast_msg('ports/%s/unbind/%s' % (port['id'], host), data)

    def _unicast_msg(self, urlfrag, msg):
        # Send unicast message to the agent running on the host
        hostname = msg['host']
        host_ip = socket.gethostbyname(hostname)
        LOG.debug("ML2_VPP: Agent host IP address: %s" % host_ip)
        agts = [ agent for agent in self.agents if host_ip in agent ]
        if agts:
            url = agts[0]
            LOG.debug("ML2_VPP: Sending message:%s to agent at:%s on host:%s" % (msg, url+urlfrag, host_ip))
            requests.put(url + urlfrag, data=msg)
        else:
            LOG.warn("ML2_VPP: Messaging to agent failed.. because the hostIP:%s" \
                     "is not found in the configured agent URL list" % host_ip)
