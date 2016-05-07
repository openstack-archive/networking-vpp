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

from oslo_config import cfg
from oslo_log import log as logging
import requests

from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api

LOG = logging.getLogger(__name__)

vpp_opts = [
    cfg.StrOpt('agents',
               help=_("HTTP URLs of agents on compute nodes.")),
]

cfg.CONF.register_opts(vpp_opts, "ml2_vpp")


class VPPMechanismDriver(api.MechanismDriver):
    supported_vnic_types = [portbindings.VNIC_NORMAL]
    allowed_network_types = [p_constants.TYPE_VLAN]

    # TODO(ijw): we have no agent registration because we're not using
    # Neutron style agents, so at the moment we make up one physical net
    # that all 'agents' are assumed to know.
    physical_networks = ['physnet1']

    def initialize(self):
        self.communicator = AgentCommunicator()

    def bind_port(self, context):
        """Attempt to bind a port.

        :param context: PortContext instance describing the port

        This method is called outside any transaction to attempt to
        establish a port binding using this mechanism driver. Bindings
        may be created at each of multiple levels of a hierarchical
        network, and are established from the top level downward. At
        each level, the mechanism driver determines whether it can
        bind to any of the network segments in the
        context.segments_to_bind property, based on the value of the
        context.host property, any relevant port or network
        attributes, and its own knowledge of the network topology. At
        the top level, context.segments_to_bind contains the static
        segments of the port's network. At each lower level of
        binding, it contains static or dynamic segments supplied by
        the driver that bound at the level above. If the driver is
        able to complete the binding of the port to any segment in
        context.segments_to_bind, it must call context.set_binding
        with the binding details. If it can partially bind the port,
        it must call context.continue_binding with the network
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
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        for segment in context.segments_to_bind:
            if self.check_segment(segment, context.host()):
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details)
                LOG.debug("Bound using segment: %s", segment)
                return

    def check_segment(self, segment, host):
        """Check if segment can be bound.

        :param segment: segment dictionary describing segment to bind
        :param host: host on which the segment must be bound to a port
        :returns: True iff segment can be bound for host

        """

        # TODO(ijw): naive - doesn't check host, or configured
        # physnets on the host

        network_type = segment[api.NETWORK_TYPE]
        if network_type not in self.allowed_network_types:
            LOG.debug(
                'Network %(network_id)s is of type %(network_type)s '
                'but this mechanism driver only '
                'support %(allowed_network_types)s.',
                {'network_id': segment['id'],
                 'network_type': network_type,
                 'allowed_network_types': self.allowed_network_types})
            return False

        if network_type not in self.allowed_network_types:
            LOG.debug(
                'Network %(network_id)s is %(network_type)s, but this driver '
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
            if not self.physnet_known(physnet):
                LOG.debug(
                    'Network %(network_id)s is connected to physical '
                    'network %(physnet)s, but the physical network '
                    ' is not one this mechdriver knows.  The physical network '
                    ' must be known if binding is to succeed.',
                    {'network_id': segment['id'],
                     'physnet': physnet}
                )
                return False

        return True

    def physnet_known(self, physnet):
        return physnet in self.physical_networks

    def check_vlan_transparency(self, context):
        """Check if the network supports vlan transparency.

        :param context: NetworkContext instance describing the network.

        In general we do not support VLAN transparency (yet).
        """
        return False

    def update_port_postcommit(self, context):
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

        current_bind = context.binding_levels.get(-1)
        prev_bind = context.original_binding_levels.get(-1)
        if current_bind is not None and \
           current_bind.BOUND_DRIVER == self:
            # then send the bind out
            self.communicator.queue_bind(context.id,
                                         context.segment,
                                         context.host())
        if prev_bind is not None and prev_bind.BOUND_DRIVER == self:
            if current_bind is None or current_bind.BOUND_DRIVER != self:
                # If we were the last binder of this port but are no longer
                self.communicator.send_unbind(context.id,
                                              context.original_host())


class AgentCommunicator(object):
    def __init__(self):
        self.agents = CONF.vpp.agents.split(';')

    def bind(self, msg):
        """Queue up a bind message for sending.

        This is called in the sequence of a REST call and should take
        as little time as possible.
        """
        # TODO(ijw): should queue the bind, not send it

        self.send_bind(msg)

    def _broadcast_msg(self, msg):
        # TODO(ijw): since we pretty much always know the host to which the
        # port is being bound or unbound, there's absolutely no reason
        # to broadcast this, but right now this saves us config work.
        # In a small cloud with not too many ports the workload on the
        # agents is not onerous.
        for url in self.agents:
            requests.put(url, msg)

    def send_bind(self, port_id, bind_type, host):
        msg = {
            'uuid': port_id,
            'bind_type': bind_type,
            'host': host,
            'bound': True
        }

        self._broadcast_msg(msg)

    def unbind(self, port_id, host):
        """Queue up an unbind message for sending.

        This is called in the sequence of a REST call and should take
        as little time as possible.
        """
        # TODO(ijw): should queue the unbind, not send it
        self.send_unbind(port_id, host)

    def send_unbind(self, port_id, host):
        msg = {
            'uuid': port_id,
            'bound': False
        }

        self.broadcast_msg(msg)
