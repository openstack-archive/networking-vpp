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

from neutron_lib import exceptions as n_exc

# TODO(ijw): backward compatibility doesn't really belong here
try:
    from neutron_lib.plugins import constants as plugin_constants
except ImportError:
    pass

try:
    # Newton release compatibility
    from neutron.db.l3_db import Router
except ImportError:
    from neutron.db.models.l3 import Router

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


class VppL3RouterPlugin(common_db_mixin.CommonDbMixin,
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
        self.gpe_physnet = cfg.CONF.ml2_vpp.gpe_locators
        LOG.info('vpp-router: router_service plugin has initialized')

    def _floatingip_path(self, fip_id):
        return (server.LEADIN + '/nodes/' + self.l3_host + '/' +
                server.ROUTER_FIP_DIR + fip_id)

    def _process_floatingip(self, context, fip_dict, event_type):
        port = self._core_plugin.get_port(context, fip_dict['port_id'])
        external_network = self._core_plugin.get_network(
            context, fip_dict['floating_network_id'])
        internal_network = self._core_plugin.get_network(
            context, port['network_id'])
        if event_type == 'associate':
            LOG.debug("Router: Associating floating ip: %s", fip_dict)
            if internal_network[provider.NETWORK_TYPE] == 'vxlan':
                internal_physnet = self.gpe_physnet
            else:
                internal_physnet = internal_network[
                    provider.PHYSICAL_NETWORK]
            vpp_floatingip_dict = {
                'external_physnet': external_network[
                    provider.PHYSICAL_NETWORK],
                'external_net_type': external_network[provider.NETWORK_TYPE],
                'external_segmentation_id':
                    external_network[provider.SEGMENTATION_ID],
                'internal_physnet': internal_physnet,
                'internal_net_type': internal_network[provider.NETWORK_TYPE],
                'internal_segmentation_id':
                    internal_network[provider.SEGMENTATION_ID],
                'fixed_ip_address': fip_dict.get('fixed_ip_address'),
                'floating_ip_address': fip_dict.get('floating_ip_address')
            }
        else:
            # Remove etcd key == disassociate floatingip
            LOG.debug("Router: disassociating floating ip: %s", fip_dict)
            vpp_floatingip_dict = None

        db.journal_write(context.session,
                         self._floatingip_path(fip_dict['id']),
                         vpp_floatingip_dict)

    def _get_vpp_router(self, context, router_id):
        try:
            router = self._get_by_id(context, Router, router_id)
        except Exception:
            raise n_exc.BadRequest("L3 Router not found for router_id: %s",
                                   router_id)
        return router

    def _get_router_interface(self, context, router_id, router_dict):

        """Populate the param: "router_dict" with values and return.

        SideEffect: Changes the parameter: router_dict
        Returns the router_dict populated with the network, subnet
        gateway ip_address, GPE locators for vxlan, network type,
        segmentation ID, is_ipv6, VRF and prefix-length information so
        vpp-agent can create the vpp router interface.

        Arguments:-
        1. router_dict: The router dictionary to be populated with data.
        It must contain the key "port_id", which is used to populate the
        router dict.
        2. router_id: Router ID

        """

        port_id = router_dict['port_id']
        port = self._core_plugin.get_port(context, port_id)
        network = self._core_plugin.get_network(context,
                                                port['network_id'])
        fixed_ips = [ip for ip in port['fixed_ips']]
        if not fixed_ips:
            n_exc.BadRequest('vpp-router-service: A router port must '
                             'have at least one fixed IP address')
        # TODO(najoy): Handle multiple fixed-ips on a router port
        fixed_ip = fixed_ips[0]
        subnet = self._core_plugin.get_subnet(context,
                                              fixed_ip['subnet_id'])
        router_dict['gateway_ip'] = fixed_ip['ip_address']
        router_dict['subnet_id'] = subnet['id']
        router_dict['fixed_ips'] = fixed_ips

        address = ip_network(subnet['cidr'])
        router_dict['network_id'] = network['id']
        router_dict['is_ipv6'] = True if address.version == 6 else False
        router_dict['prefixlen'] = address.prefixlen
        router_dict['mtu'] = network['mtu']
        router_dict['segmentation_id'] = network[provider.SEGMENTATION_ID]
        router_dict['net_type'] = network[provider.NETWORK_TYPE]
        if router_dict['net_type'] == 'vxlan':
            router_dict['physnet'] = self.gpe_physnet
        else:
            router_dict['physnet'] = network[provider.PHYSICAL_NETWORK]
        # Get VRF corresponding to the router
        vrf_id = db.get_router_vrf(context.session, router_id)
        router_dict['vrf_id'] = vrf_id
        return router_dict

    def _get_router_intf_path(self, router_id, port_id):
        return (server.LEADIN + '/nodes/' +
                self.l3_host + '/' + server.ROUTERS_DIR +
                router_id + '/' + port_id)

    def _write_interface_journal(self, context, router_id, router_dict):
        LOG.info("router-service: writing router interface journal for "
                 "router_id:%s, router_dict:%s", router_id, router_dict)
        router_intf_path = self._get_router_intf_path(
            router_id,
            router_dict['port_id'])
        db.journal_write(context.session, router_intf_path, router_dict)
        self.communicator.kick()

    def _remove_interface_journal(self, context, router_id, port_id):
        LOG.info("router-service: removing router interface journal for "
                 "router_id:%s, port_id:%s", router_id, port_id)
        router_intf_path = self._get_router_intf_path(
            router_id,
            port_id)
        db.journal_write(context.session, router_intf_path, None)
        self.communicator.kick()

    def _write_router_external_gw_journal(self, context, router_id,
                                          router_dict, delete=False):
        LOG.info("Writing router external gateway using router_dict: %s",
                 router_dict)
        router_dict['vrf_id'] = db.get_router_vrf(context.session, router_id)
        # Get the external network details
        network = self._core_plugin.get_network(
            context, router_dict['external_gateway_info']['network_id'])
        LOG.debug("Router external gateway network data: %s", network)
        # Grab the external network info
        router_dict['external_physnet'] = network[provider.PHYSICAL_NETWORK]
        router_dict['external_segmentation_id'] = network[
            provider.SEGMENTATION_ID]
        router_dict['external_net_type'] = network[provider.NETWORK_TYPE]
        router_dict['mtu'] = network['mtu']
        # The Neutron port created for the gateway
        gateway_port = router_dict['gw_port_id']
        # Get the mac-addr of the port to create the port
        if not delete:
            gw_port = self._core_plugin.get_port(context, gateway_port)
            router_dict['loopback_mac'] = gw_port['mac_address']
        # Grab all external subnets' gateway IPs
        # This is added to the router dictionary using the key: gateways
        # The value of gateways is a list of tuples:
        # (gateway_ip, prefix_len, is_ipv6)
        fixed_ips = router_dict['external_gateway_info']['external_fixed_ips']
        gateways = []
        # For each subnet/fixed-ip, write a key to create a gateway uplink
        # on that subnet with the correct IP address
        for fixed_ip in fixed_ips:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._core_plugin.get_subnet(context, subnet_id)
            address = ip_network(subnet['cidr'])
            is_ipv6 = True if address.version == 6 else False
            gateways.append((fixed_ip['ip_address'],
                             address.prefixlen,
                             is_ipv6))
            # IP addresses to be set on VPP's external interface connecting
            # to an external gateway
            router_dict['gateways'] = gateways
            # This the IP address of the external gateway that functions as
            # the default gateway for the tenant's router
            router_dict['external_gateway_ip'] = subnet['gateway_ip']
            etcd_key = self._get_router_intf_path(router_id, gateway_port)
            if delete:
                router_dict = None
            db.journal_write(context.session, etcd_key, router_dict)
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
                self._write_router_external_gw_journal(
                    context, router_dict['id'], router_dict)

        return router_dict

    def update_router(self, context, router_id, router):
        # Get the old router for comparison
        old_router = self.get_router(context, router_id)
        new_router = super(VppL3RouterPlugin, self).update_router(
            context, router_id, router)
        ext_gw = 'external_gateway_info'
        # If external gateway has changed, delete the old external gateway
        # states from etcd and write the new states, if we have a new valid
        # external gateway
        if old_router[ext_gw] != new_router[ext_gw]:
            # If the old router has an external gateway delete and then set
            # the new router's external gateway
            if old_router[ext_gw]:
                self._write_router_external_gw_journal(context, router_id,
                                                       old_router,
                                                       delete=True)
            if new_router[ext_gw]:
                self._write_router_external_gw_journal(context, router_id,
                                                       new_router)

        return new_router

    def delete_router(self, context, router_id):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            router = self.get_router(context, router_id)
            super(VppL3RouterPlugin, self).delete_router(context, router_id)
            # Delete the external gateway key from etcd
            if router.get('external_gateway_info', False):
                self._write_router_external_gw_journal(context, router_id,
                                                       router, delete=True)
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

    def _get_router_port_on_subnet(self, context, router_id, router_dict):
        filters = {'device_id': [router_id]}
        router_ports = self._core_plugin.get_ports(context,
                                                   filters=filters)
        fixed_ip = router_dict['fixed_ips'][0]
        subnet_id = fixed_ip['subnet_id']
        ip_address = fixed_ip['ip_address']
        LOG.info("Router ports on subnet: %s == %s",
                 subnet_id, router_ports)
        router_port = [port for port in router_ports
                       if port['fixed_ips'][0]['subnet_id'] == subnet_id
                       and port['fixed_ips'][0]['ip_address'] == ip_address]
        if router_port:
            return router_port[0]['id']
        else:
            LOG.error("A router port could not be found on subnet: %s",
                      router_dict['subnet_id'])

    @kick_communicator_on_end
    def add_router_interface(self, context, router_id, interface_info):
        """Add a router port to a subnet or bind it to an existing port.

        There are two ways to add a router interface. The interface_info
        can provide a subnet using the 'subnet_id' key or a port using the
        'port_id' key.
        """
        LOG.info("router_service: interface_info: %s", interface_info)
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            new_router = super(VppL3RouterPlugin, self).add_router_interface(
                context, router_id, interface_info)
            LOG.info("Add router interface: New router is: %s",
                     new_router)
            # (najoy) We should use the router port's mac-address instead of
            # a random mac-address
            router_dict = {}
            port_id = new_router['port_id']
            port = self._core_plugin.get_port(context, port_id)
            router_dict['port_id'] = port_id
            router_dict['loopback_mac'] = port['mac_address']
            router_dict = self._get_router_interface(context, router_id,
                                                     router_dict
                                                     )
            router = self._get_vpp_router(context, router_id)
            port_data = {'tenant_id': router.tenant_id,
                         'network_id': router_dict['network_id'],
                         'fixed_ips': router_dict['fixed_ips'],
                         'device_id': router.id,
                         'device_owner': 'vpp-router'
                         }

            self._core_plugin.update_port(context, port_id,
                                          {'port': port_data})

            self._write_interface_journal(context, router_id, router_dict)

        return new_router

    @kick_communicator_on_end
    def remove_router_interface(self, context, router_id, interface_info):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            new_router = super(
                VppL3RouterPlugin, self).remove_router_interface(
                context, router_id, interface_info)
            LOG.info("Remove router interface: New router is: %s",
                     new_router)
            port_id = new_router['port_id']
            self._core_plugin.delete_port(context,
                                          port_id,
                                          l3_port_check=False)
            self._remove_interface_journal(context, router_id, port_id)

        return new_router
