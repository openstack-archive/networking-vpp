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

import mock
import sys
sys.modules['vpp_papi'] = mock.MagicMock()
from networking_vpp.agent import server
from neutron.tests import base


class VPPForwarderTestCase(base.BaseTestCase):
    _mechanism_drivers = ['vpp']

    @mock.patch('networking_vpp.agent.server.vpp')
    @mock.patch('networking_vpp.agent.server.vpp.VPPInterface.get_interface')
    def setUp(self, m_vpp, m_vppif):
        super(VPPForwarderTestCase, self).setUp()
        self.vpp = server.VPPForwarder({"test_net": "test_iface"})

    def test_get_vpp_ifidx(self):
        type(self.vpp.vpp.get_interface.return_value).sw_if_index = 1
        sw_if_return = self.vpp.get_vpp_ifidx('test')
        self.vpp.vpp.get_interface.assert_called_with('test')
        assert (sw_if_return == 1), "Return value should have been 1"

    def test_get_interface(self):
        retval = self.vpp.get_interface('test_net')
        assert (retval == 'test_iface'), \
            "Return value should have been test_iface"

    def test_new_bridge_domain(self):
        bridge_id = 5678
        self.vpp.new_bridge_domain()
        self.vpp.vpp.create_bridge_domain.assert_called_once_with(bridge_id)
        assert (self.vpp.next_bridge_id == 5679),\
            "Bridge ID should now be 5679"

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.create_network_on_host')
    def test_no_network_on_host(self, m_create_network_on_host):
        physnet = 'test'
        self.vpp.network_on_host(physnet, 'flat')
        assert m_create_network_on_host.called_once_with(physnet, 'flat', None)

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.create_network_on_host')
    def test_yes_network_on_host(self, m_create_network_on_host):
        physnet = 'test'
        self.vpp.networks = {(physnet, 'flat', None): 'test'}
        retval = self.vpp.network_on_host(physnet, 'flat')
        assert(retval == 'test'), "Return network value should be 'test'"

    def test_none_create_network_on_host(self):
        retval = self.vpp.create_network_on_host('not_there', 'flat', None)
        assert (retval is None), "Return value should have been None"

    def test_flat_create_network_on_host(self):
        net_length = len(self.vpp.networks)
        type(self.vpp.vpp.get_interface.return_value).sw_if_index = 1
        self.vpp.create_network_on_host('test_net', 'flat', '1')
        self.vpp.vpp.ifup.assert_called_once_with(1)
        self.vpp.vpp.add_to_bridge.called_once_with(5679, 1)
        assert (len(self.vpp.networks) > net_length), \
            "There should be one more network now"

    def test_vlan_create_network_on_host(self):
        net_length = len(self.vpp.networks)
        type(self.vpp.vpp.get_interface.return_value).sw_if_index = 1
        self.vpp.vpp.get_interface('test_iface.1').return_value = 1
        self.vpp.create_network_on_host('test_net', 'vlan', '1')
        self.vpp.vpp.ifup.assert_called_with(1)
        self.vpp.vpp.add_to_bridge.assert_called_once_with(5678, 1)
        assert (len(self.vpp.networks) > net_length), \
            "There should be one more network now"

    def test_delete_network_on_host(self):
        physnet = 'test'
        self.vpp.networks = {(physnet, 'flat', None): {'bridge_domain_id': 1}}
        self.vpp.delete_network_on_host(physnet, 'flat')
        self.vpp.vpp.delete_bridge_domain.assert_called_once_with(1)

    @mock.patch('networking_vpp.agent.server.ip_lib')
    def test_bridge_exists_and_ensure_up(self, m_ip_lib):
        retval = self.vpp._bridge_exists_and_ensure_up('test')
        assert (retval is True), "Bridge link should have been found"

    @mock.patch('networking_vpp.agent.server.bridge_lib')
    def test_ensure_bridge(self):
        self.vpp.ensure_bridge('test_br')

    def test_add_external_tap(self):
        pass

    def test_create_interface_on_host(self):
        pass

    def test_bind_interface_on_host(self):
        pass

    def test_unbind_interface_on_host(self):
        pass
