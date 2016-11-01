# Copyright (c) 2017 Cisco Systems, Inc.
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

import mock

from networking_vpp.compat import context
from networking_vpp.compat import directory
from networking_vpp.compat import n_const as constants
from networking_vpp.db import db
from networking_vpp.services.l3_router import l3_vpp

from neutron.db import api as neutron_db_api
from neutron.extensions import external_net as external_net
from neutron.plugins.ml2 import config
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2

from oslo_config import cfg
from sqlalchemy.orm import exc


class VppL3PluginTestCase(
    test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
    base.BaseTestCase):

    @mock.patch('networking_vpp.mech_vpp.EtcdAgentCommunicator')
    def setUp(self, m_etcd):
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'vpp'], 'ml2')
        config.cfg.CONF.set_override('core_plugin',
                                     'neutron.plugins.ml2.plugin.Ml2Plugin')
        cfg.CONF.set_override('service_plugins', ['vpp-router'])
        core_plugin = cfg.CONF.core_plugin
        service_plugins = {'l3_plugin_name': 'vpp-router'}
        mock.patch.object(l3_vpp, 'EtcdAgentCommunicator').start()
        super(VppL3PluginTestCase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins)
        self.db_session = neutron_db_api.get_session()
        self.plugin = directory.get_plugin()
        self.plugin._network_is_external = mock.Mock(return_value=True)
        self.driver = directory.get_plugin(constants.L3)

    @staticmethod
    def _get_mock_router_operation_info(network, subnet):
        router_context = context.get_admin_context()
        router = {'router':
                  {'name': 'router1',
                   'admin_state_up': True,
                   'tenant_id': network['network']['tenant_id'],
                   'external_gateway_info': {'network_id':
                                             network['network']['id']}}}
        return router_context, router

    @staticmethod
    def _get_mock_floatingip_operation_info(network, subnet):
        floatingip_context = context.get_admin_context()
        floatingip = {'router':
                      {'floating_network_id': network['network']['id'],
                       'tenant_id': network['network']['tenant_id']}}
        return floatingip_context, floatingip

    @staticmethod
    def _get_mock_router_interface_operation_info(network, subnet):
        router_intf_context = context.get_admin_context()
        router_intf_dict = {'subnet_id': subnet['subnet']['id'],
                            'id': network['network']['id']}
        return router_intf_context, router_intf_dict

    def test_router_create_vrf_reserved(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.network(**kwargs) as network:
            router_context, router_dict = (
                self._get_mock_router_operation_info(network, None))
            new_router_dict = self.driver.create_router(router_context,
                                                        router_dict)
            # Check if a VRf was allocated to this router
            vrf = db.get_router_vrf(self.db_session, new_router_dict['id'])
            self.assertIsNotNone(vrf)

    def test_router_delete_vrf_unreserved(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.network(**kwargs) as network:
            router_context, router_dict = (
                self._get_mock_router_operation_info(network, None))
            new_router_dict = self.driver.create_router(router_context,
                                                        router_dict)
            # Check if the VRF is unallocated on a delete
            self.driver.delete_router(router_context, new_router_dict['id'])
            self.assertRaises(exc.NoResultFound, db.get_router_vrf,
                              self.db_session, new_router_dict['id'])

    def test_add_remove_router_interface_journal_row(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.network(**kwargs) as network:
            with self.subnet(cidr='10.0.0.0/24') as subnet:
                router_context, router_dict = (
                    self._get_mock_router_operation_info(network, None))
                new_router_dict = self.driver.create_router(router_context,
                                                            router_dict)
                router_intf_context, router_intf_dict = (
                    self._get_mock_router_interface_operation_info(
                        network, subnet))
                self.driver.add_router_interface(
                    router_intf_context, new_router_dict['id'],
                    router_intf_dict)
                rows = db.get_all_journal_rows(self.db_session)
                self.assertEqual(len(rows), 1)

                self.driver.remove_router_interface(
                    router_intf_context, new_router_dict['id'],
                    router_intf_dict)
                rows = db.get_all_journal_rows(self.db_session)
                self.assertEqual(len(rows), 2)
