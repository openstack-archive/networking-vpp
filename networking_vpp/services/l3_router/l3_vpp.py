#  Copyright (c) 2017 Cisco Systems, Inc.
#  All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
#

from ipaddress import ip_network

from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.extensions import providernet as provider
from neutron_lib import constants

from networking_vpp.agent import server
from networking_vpp.db import db
from networking_vpp.mech_vpp import EtcdAgentCommunicator

LOG = logging.getLogger(__name__)


class VppL3RouterPlugin(
    common_db_mixin.CommonDbMixin,
    extraroute_db.ExtraRoute_db_mixin,
    l3_gwmode_db.L3_NAT_db_mixin):

    """Implementation of the VPP L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    """
    supported_extension_aliases = ["router", "ext-gw-mode"]

    def __init__(self):
        super(VppL3RouterPlugin, self).__init__()
        self.communicator = EtcdAgentCommunicator()
        self.l3_host = cfg.CONF.ml2_vpp.l3_host

    def _get_physnet(self):
        # Get physnet corresponding to the L3 host
        for (host, physnet) in self.communicator.find_physnets():
            if host == self.l3_host:
                return physnet

    def _floatingip_path(self, fip_id):
        return (server.LEADIN + '/nodes/' + self.l3_host +
                '/server.ROUTER_FIP_DIR/' + fip_id)

    def _process_floatingip(self, context, fip_dict, event_type):
        port = self._core_plugin.get_port(context, fip_dict['port_id'])
        external_network = self._core_plugin.get_network(
            context, fip_dict['floating_network_id'])
        internal_network = self._core_plugin.get_network(
            context, port['network_id'])

        vpp_floatingip_dict = {
            'physnet': self._get_physnet(),
            'external_net_type': external_network[provider.NETWORK_TYPE],
            'external_segmentation_id':
                external_network[provider.SEGMENTATION_ID],
            'internal_net_type': internal_network[provider.NETWORK_TYPE],
            'internal_segmentation_id':
                internal_network[provider.SEGMENTATION_ID],
            'fixed_ip_address': fip_dict.get('fixed_ip_address'),
            'floating_ip_address': fip_dict.get('floating_ip_address'),
            'event': event_type,
        }

        db.journal_write(context.session,
                         self._floatingip_path(fip_dict['id']),
                         vpp_floatingip_dict)
        self.communicator.kick()

    def get_plugin_type(self):
        return constants.L3

    def get_plugin_description(self):
        """Returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding "
                "using VPP.")

    def create_router(self, context, router):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            router_dict = super(VppL3RouterPlugin, self).create_router(
                context, router)
            # Allocate VRF for this router
            db.add_router_vrf(context.session, router_dict['id'])

        return router_dict

    def delete_router(self, context, router_id):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            super(VppL3RouterPlugin, self).delete_router(context, router_id)
            # Delete VRF allocation for this router
            db.delete_router_vrf(context.session, router_id)

    def create_floatingip(self, context, floatingip):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            fip_dict = super(VppL3RouterPlugin, self).create_floatingip(
                context, floatingip,
                initial_status=constants.FLOATINGIP_STATUS_ACTIVE)
            if fip_dict.get('port_id') is not None:
                self._process_floatingip(context, fip_dict, 'associate')

        return fip_dict

    def update_floatingip(self, context, floatingip_id, floatingip):
        org_fip_dict = self.get_floatingip(context, floatingip_id)
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            fip_dict = super(VppL3RouterPlugin, self).update_floatingip(
                context, floatingip_id, floatingip)
            if fip_dict.get('port_id') is not None:
                event_type = 'associate'
                vpp_fip_dict = fip_dict
            else:
                event_type = 'disassociate'
                vpp_fip_dict = org_fip_dict
            self._process_floatingip(context, vpp_fip_dict, event_type)

        return fip_dict

    def delete_floatingip(self, context, floatingip_id):
        org_fip_dict = self.get_floatingip(context, floatingip_id)
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            super(VppL3RouterPlugin, self).delete_floatingip(
                context, floatingip_id)
            if org_fip_dict.get('port_id') is not None:
                self._process_floatingip(context, org_fip_dict, 'disassociate')

    def _get_router_intf_details(self, context, router_id, interface_info,
                                 router_dict):
        # Returns a router dictionary populated with network and
        # subnet information for the associated subnet

        # Get vlan id for this subnet's network
        subnet = self._core_plugin.get_subnet(
            context, interface_info['subnet_id'])
        network = self._core_plugin.get_network(
            context, subnet['network_id'])
        router_dict['segmentation_id'] = network[provider.SEGMENTATION_ID]
        router_dict['net_type'] = network[provider.NETWORK_TYPE]
        # Get VRF corresponding to the router
        vrf_id = db.get_router_vrf(context.session, router_id)
        router_dict['vrf_id'] = vrf_id
        # Get internal gateway address for this subnet
        router_dict['gateway_ip'] = subnet['gateway_ip']
        # Get prefix and type for this subnet
        router_dict['is_ipv6'] = False
        address = ip_network(subnet['cidr'])
        if address.version == 6:
            router_dict['is_ipv6'] = True
        router_dict['prefixlen'] = address.prefixlen

        # Get physnet corresponding to the L3 host
        for (host, physnet) in self.communicator.find_physnets():
            if host == self.l3_host:
                router_dict['physnet'] = physnet
                break

    def add_router_interface(self, context, router_id, interface_info):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            new_router = super(VppL3RouterPlugin, self).add_router_interface(
                context, router_id, interface_info)
            router_dict = {}
            # Get a random mac address for loopback
            mac = utils.get_random_mac(cfg.CONF.base_mac.split(':'))
            router_dict['loopback_mac'] = mac
            self._get_router_intf_details(context, router_id,
                                          interface_info, router_dict)
            db.journal_write(
                context.session,
                (server.LEADIN + '/nodes/' + self.l3_host +
                 '/server.ROUTER_INTF_DIR/' + router_id),
                router_dict)
            self.communicator.kick()

        return new_router

    def remove_router_interface(self, context, router_id, interface_info):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            new_router = super(
                VppL3RouterPlugin, self).remove_router_interface(
                context, router_id, interface_info)
            router_dict = {}
            router_dict['delete'] = True
            self._get_router_intf_details(context, router_id,
                                          interface_info, router_dict)

            db.journal_write(
                context.session,
                (server.LEADIN + '/nodes/' + self.l3_host +
                 '/server.ROUTER_INTF_DIR/' + router_id),
                router_dict)
            self.communicator.kick()

        return new_router
