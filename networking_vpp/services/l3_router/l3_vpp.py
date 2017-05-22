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

from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import l3_gwmode_db
from neutron_lib.api.definitions import provider_net as provider
from neutron_lib import constants

from networking_vpp.compat import net_utils

# TODO(ijw): backward compatibility doesn't really belong here
try:
    from neutron_lib.plugins import constants as plugin_constants
except ImportError:
    pass

from networking_vpp.agent import server
from networking_vpp.db import db
from networking_vpp.mech_vpp import EtcdAgentCommunicator

LOG = logging.getLogger(__name__)


def kick_communicator_on_end(func):
    # Give the etcd communicator a kick after the method returns
    def new_func(obj, *args, **kwargs):
        return_value = func(obj, *args, **kwargs)
        obj.communicator.kick()
        return return_value
    return new_func


class VppL3RouterPlugin(
    common_db_mixin.CommonDbMixin,
    l3_gwmode_db.L3_NAT_dbonly_mixin):

    """Implementation of the VPP L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    """
    supported_extension_aliases = ["router", "ext-gw-mode"]

    def __init__(self):
        super(VppL3RouterPlugin, self).__init__()
        self.communicator = EtcdAgentCommunicator(
            notify_bound=lambda *args: None)
        self.l3_host = cfg.CONF.ml2_vpp.l3_host

    def _floatingip_path(self, fip_id):
        return (server.LEADIN + '/nodes/' + self.l3_host + '/' +
                server.ROUTER_FIP_DIR + fip_id)

    def _process_floatingip(self, context, fip_dict, event_type):
        port = self._core_plugin.get_port(context, fip_dict['port_id'])
        external_network = self._core_plugin.get_network(
            context, fip_dict['floating_network_id'])
        internal_network = self._core_plugin.get_network(
            context, port['network_id'])

        vpp_floatingip_dict = {
            'external_physnet': external_network[provider.PHYSICAL_NETWORK],
            'external_net_type': external_network[provider.NETWORK_TYPE],
            'external_segmentation_id':
                external_network[provider.SEGMENTATION_ID],
            'internal_physnet': internal_network[provider.PHYSICAL_NETWORK],
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

    def _get_router_intf_details(self, context, router_id, interface_info,
                                 router_dict):
        # Returns a router dictionary populated with network and
        # subnet information for the associated subnet

        # Get vlan id for this subnet's network
        subnet = self._core_plugin.get_subnet(
            context, interface_info['subnet_id'])
        network = self._core_plugin.get_network(
            context, subnet['network_id'])
        router_dict['mtu'] = network['mtu']
        router_dict['segmentation_id'] = network[provider.SEGMENTATION_ID]
        router_dict['net_type'] = network[provider.NETWORK_TYPE]
        router_dict['physnet'] = network[provider.PHYSICAL_NETWORK]
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

    def _write_interface_journal(self, context, router_id, router_dict):
        etcd_dir = (server.LEADIN + '/nodes/' + self.l3_host + '/' +
                    server.ROUTER_INTF_DIR + router_id)
        db.journal_write(context.session, etcd_dir, router_dict)
        self.communicator.kick()

    def _write_router_journal(self, context, router_id, router_dict):
        etcd_dir = (server.LEADIN + '/nodes/' + self.l3_host + '/' +
                    server.ROUTER_DIR + router_id)
        router_dict['vrf_id'] = db.get_router_vrf(context.session, router_id)
        # Get the external network details
        network = self._core_plugin.get_network(
            context, router_dict['external_gateway_info']['network_id'])
        # Grab the external network info
        router_dict['external_physnet'] = network[provider.PHYSICAL_NETWORK]
        router_dict['external_segment'] = network[provider.SEGMENTATION_ID]
        router_dict['external_net_type'] = network[provider.NETWORK_TYPE]
        # Grab all external subnets' gateway IPs
        # This is added to the router dictionary in the format:
        # [(Router's IP Address from the external network's subnet,
        #   External Subnet's prefix)]
        fixed_ips = router_dict['external_gateway_info']['external_fixed_ips']
        gateways = []
        for fixed_ip in fixed_ips:
            subnet = self._core_plugin.get_subnet(
                context, fixed_ip['subnet_id'])
            gateways.append((fixed_ip['ip_address'],
                            ip_network(subnet['cidr']).prefixlen))
        router_dict['gateways'] = gateways
        db.journal_write(context.session, etcd_dir, router_dict)
        self.communicator.kick()

    def get_plugin_type(self):
        # TODO(ijw): not really the right place for backward compatibility...
        try:
            return plugin_constants.L3
        except Exception:
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
            if router_dict.get('external_gateway_info', False):
                self._write_router_journal(
                    context, router_dict['id'], router_dict)

        return router_dict

    def update_router(self, context, router_id, router):
        # Get the old router for comparison
        old_router = self.get_router(context, router_id)
        new_router = super(VppL3RouterPlugin, self).update_router(
            context, router_id, router)
        # Check if the gateway changed
        ext_gw = 'external_gateway_info'
        if old_router[ext_gw] != new_router[ext_gw]:
            # Check if the gateway has been removed
            if not new_router[ext_gw]:
                # Populate values from the old router
                new_router[ext_gw] = old_router[ext_gw]
                new_router['delete'] = True
            # Update dictionary values
            self._write_router_journal(context, router_id, new_router)

        return new_router

    def delete_router(self, context, router_id):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            router = self.get_router(context, router_id)
            super(VppL3RouterPlugin, self).delete_router(context, router_id)
            if router.get('external_gateway_info', False):
                router['delete'] = True
                self._write_router_journal(context, router_id,
                                           router)
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

        if fip_dict.get('port_id') is not None:
            self.communicator.kick()

        return fip_dict

    @kick_communicator_on_end
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

        if org_fip_dict.get('port_id') is not None:
            self.communicator.kick()

    @kick_communicator_on_end
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        fips = self.get_floatingips(context.elevated(),
                                    filters={'port_id': [port_id]})
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            router_ids = super(
                VppL3RouterPlugin, self).disassociate_floatingips(
                context, port_id, do_notify)
            for fip in fips:
                self._process_floatingip(context, fip, 'disassociate')
        return router_ids

    @kick_communicator_on_end
    def add_router_interface(self, context, router_id, interface_info):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            new_router = super(VppL3RouterPlugin, self).add_router_interface(
                context, router_id, interface_info)
            router_dict = {}
            # Get a random mac address for loopback
            mac = net_utils.get_random_mac(cfg.CONF.base_mac.split(':'))
            router_dict['loopback_mac'] = mac
            self._get_router_intf_details(context, router_id,
                                          interface_info, router_dict)
            self._write_interface_journal(context, router_id, router_dict)

        return new_router

    @kick_communicator_on_end
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
            self._write_interface_journal(context, router_id, router_dict)

        return new_router
