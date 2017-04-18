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
import sys

sys.modules['vpp_papi'] = mock.MagicMock()

from networking_vpp.compat import context
from networking_vpp.compat import directory
from networking_vpp.compat import n_const as constants
from networking_vpp.db import db
from networking_vpp.services.l3_router import l3_vpp

from neutron.db import api as neutron_db_api
from neutron.db import l3_db
from neutron.extensions import external_net as external_net
from neutron.plugins.ml2 import config
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron_lib.api.definitions import provider_net as provider

from oslo_config import cfg

FLOATINGIP_ID = 'floatingip_uuid'
NETWORK_ID = 'network_uuid'
ROUTER_ID = 'router_uuid'
SUBNET_ID = 'subnet_uuid'
PORT_ID = 'port_uuid'

PORT_DICT = {'network_id': NETWORK_ID}

NETWORK_DICT = {
    provider.NETWORK_TYPE: 'vlan',
    provider.SEGMENTATION_ID: '123',
    provider.PHYSICAL_NETWORK: 'fake_physnet'}

FLOATINGIP_DICT = {
    'router_id': ROUTER_ID,
    'floating_network_id': NETWORK_ID,
    'port_id': PORT_ID,
    'fixed_ip_address': '1.2.3.4',
    'floating_ip_address': '2.3.4.5',
    'id': FLOATINGIP_ID}


class VppL3PluginBaseTestCase(
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
        super(VppL3PluginBaseTestCase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins)
        self.db_session = neutron_db_api.get_session()
        self.plugin = directory.get_plugin()
        self.plugin._network_is_external = mock.Mock(return_value=True)
        self.driver = directory.get_plugin(constants.L3)

    @staticmethod
    def _get_mock_router_operation_info(network, subnet):
        router_context = context.get_admin_context()
        router = {'router':
                  {'id': '8f3ad881-b92a-47f9-b644-63e56e265ddd',
                   'name': 'router1',
                   'admin_state_up': True,
                   'tenant_id': network['network']['tenant_id'],
                   'external_gateway_info': {}}}
        return router_context, router

    @staticmethod
    def _get_mock_router_with_gateway_operation_info(network, subnet):
        router_context = context.get_admin_context()
        router = {'router':
                  {'id': '8f3ad881-b92a-47f9-b644-63e56e265ddd',
                   'name': 'router1',
                   'admin_state_up': True,
                   'tenant_id': network['network']['tenant_id'],
                   'external_gateway_info': {'network_id':
                                             network['network']['id']}}}
        return router_context, router

    @staticmethod
    def _get_mock_floatingip_operation_info(network, subnet):
        floatingip_context = context.get_admin_context()
        floatingip = {'floatingip':
                      {'floating_network_id': network['network']['id'],
                       'tenant_id': network['network']['tenant_id'],
                       'port_id': PORT_ID}}
        return floatingip_context, floatingip

    @staticmethod
    def _get_mock_router_interface_operation_info(network, subnet):
        router_intf_context = context.get_admin_context()
        router_intf_dict = {'subnet_id': subnet['subnet']['id'],
                            'id': network['network']['id']}
        return router_intf_context, router_intf_dict


class VppL3PluginRouterInterfaceTestCase(VppL3PluginBaseTestCase):

    def setUp(self):
        super(VppL3PluginRouterInterfaceTestCase, self).setUp()

    def test_router_create_vrf_reserved(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: False}
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
                  external_net.EXTERNAL: False}
        with self.network(**kwargs) as network:
            router_context, router_dict = (
                self._get_mock_router_operation_info(network, None))
            new_router_dict = self.driver.create_router(router_context,
                                                        router_dict)
            # Check if the VRF is unallocated on a delete
            self.driver.delete_router(router_context, new_router_dict['id'])
            self.assertIsNone(
                db.get_router_vrf(self.db_session, new_router_dict['id']))

    def test_add_remove_router_interface_journal_row(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: False}
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


class VppL3PluginFloatingIPsTestCase(VppL3PluginBaseTestCase):

    def setUp(self):
        super(VppL3PluginFloatingIPsTestCase, self).setUp()
        self.floatingip = {'floatingip': FLOATINGIP_DICT}
        self.plugin.get_port = mock.Mock(return_value=PORT_DICT)
        self.plugin.get_network = mock.Mock(return_value=NETWORK_DICT)
        self.context = context.get_admin_context()
        self.create_mock = mock.patch.object(
            l3_db.L3_NAT_dbonly_mixin, 'create_floatingip',
            return_value=FLOATINGIP_DICT).start()
        self.update_mock = mock.patch.object(
            l3_db.L3_NAT_dbonly_mixin, 'update_floatingip',
            return_value=FLOATINGIP_DICT).start()
        self.delete_mock = mock.patch.object(
            l3_db.L3_NAT_dbonly_mixin, 'delete_floatingip').start()
        self.get_floatingip = mock.patch.object(
            l3_db.L3_NAT_dbonly_mixin, 'get_floatingip',
            return_value=FLOATINGIP_DICT).start()

    def test_floatingip_journal_row(self):
        """Test calling create,update,delete floatingip creates DB entries."""

        mock_journal_write = mock.patch.object(db, 'journal_write').start()

        self.driver.create_floatingip(self.context, self.floatingip)
        self.assertEqual(mock_journal_write.call_count, 1)

        self.driver.update_floatingip(self.context, FLOATINGIP_ID,
                                      self.floatingip)
        self.assertEqual(mock_journal_write.call_count, 2)

        self.driver.delete_floatingip(self.context, FLOATINGIP_ID)
        self.assertEqual(mock_journal_write.call_count, 3)

    def test_floatingip_create_no_port(self):
        """Test calling create floatingip without a port ID."""

        floatingip_dict_no_port = FLOATINGIP_DICT.copy()
        floatingip_dict_no_port.pop('port_id', None)

        mock_process_floatingip = mock.patch.object(
            l3_vpp.VppL3RouterPlugin, '_process_floatingip').start()
        self.create_mock.return_value = floatingip_dict_no_port

        self.driver.create_floatingip(self.context, self.floatingip)

        self.assertEqual(mock_process_floatingip.called, False)

    def test_floatingip_update_no_port(self):
        """Test calling update floatingip without a port ID."""

        floatingip_dict_no_port = FLOATINGIP_DICT.copy()
        floatingip_dict_no_port.pop('port_id', None)

        mock_process_floatingip = mock.patch.object(
            l3_vpp.VppL3RouterPlugin, '_process_floatingip').start()

        self.update_mock.return_value = floatingip_dict_no_port

        self.driver.update_floatingip(self.context, FLOATINGIP_ID,
                                      self.floatingip)

        mock_process_floatingip.assert_called_once_with(
            mock.ANY, mock.ANY, 'disassociate')

    def test_floatingip_delete_no_port(self):
        """Test calling delete floatingip without a port ID."""

        floatingip_dict_no_port = FLOATINGIP_DICT.copy()
        floatingip_dict_no_port.pop('port_id', None)

        mock_process_floatingip = mock.patch.object(
            l3_vpp.VppL3RouterPlugin, '_process_floatingip').start()
        self.get_floatingip.return_value = floatingip_dict_no_port

        self.driver.delete_floatingip(self.context, FLOATINGIP_ID)

        self.assertEqual(mock_process_floatingip.called, False)


class VppL3PluginRouterTestCase(VppL3PluginBaseTestCase):

    def setUp(self):
        super(VppL3PluginRouterTestCase, self).setUp()

    def test_create_router_without_gateway_no_journal_row(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: False}
        with self.network(**kwargs) as network:
            with self.subnet(cidr='10.0.0.0/24'):
                router_context, router_dict = (
                    self._get_mock_router_operation_info(network, None))
                self.driver.create_router(router_context, router_dict)
                rows = db.get_all_journal_rows(self.db_session)
                self.assertEqual(len(rows), 0)

    def test_create_router_with_gateway_journal_row(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.network(**kwargs) as network:
            with self.subnet(cidr='50.0.0.0/24'):
                router_context, router_dict = (
                    self._get_mock_router_with_gateway_operation_info(
                        network, None))

                self.driver.create_router(router_context, router_dict)
                rows = db.get_all_journal_rows(self.db_session)
                self.assertEqual(len(rows), 1)

    def test_update_router_with_gateway_journal_row(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: False}
        with self.network(**kwargs) as network:
            with self.subnet(cidr='10.0.0.0/24'):
                router_context, router_dict = (
                    self._get_mock_router_operation_info(network, None))
                self.driver.create_router(router_context, router_dict)

                kwargs[external_net.EXTERNAL] = True
                with self.network(**kwargs) as network:
                    with self.subnet(cidr='10.0.0.0/24'):
                        router_context, new_router_dict = (
                            self._get_mock_router_with_gateway_operation_info(
                                network, None))
                        self.driver.update_router(
                            router_context, new_router_dict['router']['id'],
                            new_router_dict)

                        rows = db.get_all_journal_rows(self.db_session)
                        self.assertEqual(len(rows), 1)

    def test_delete_router_with_gateway_journal_row(self):
        # Create network, subnet and router for testing.
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.network(**kwargs) as network:
            with self.subnet(cidr='50.0.0.0/24'):
                router_context, router_dict = (
                    self._get_mock_router_with_gateway_operation_info(
                        network, None))

                self.driver.create_router(router_context, router_dict)
                self.driver.delete_router(
                    router_context, router_dict['router']['id'])
                rows = db.get_all_journal_rows(self.db_session)
                self.assertEqual(len(rows), 2)
