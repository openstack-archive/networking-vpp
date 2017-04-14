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
from neutron.db import l3_gwmode_db
from neutron_lib.api.definitions import provider_net as provider
from neutron_lib import constants

from networking_vpp.db import db
from networking_vpp.mech_vpp import EtcdAgentCommunicator

LOG = logging.getLogger(__name__)

LEADIN = '/networking-vpp'


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

    def _get_router_intf_details(self, context, router_id, interface_info,
                                 router_dict):
        # Returns a router dictionary populated with network and
        # subnet information for the associated subnet

        # Get segmentation details for this subnet's network
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

    def _write_journal_row(self, context, router_id, router_dict):
        etcd_dir = LEADIN + '/nodes/' + self.l3_host + '/routers/' + router_id
        db.journal_write(context.session, etcd_dir, router_dict)

    @kick_communicator_on_end
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
            self._write_journal_row(context, router_id, router_dict)

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
            self._write_journal_row(context, router_id, router_dict)

        return new_router
