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
sys.modules['threading'] = mock.MagicMock()
from networking_vpp.agent import server
from neutron.tests import base


class VPPForwarderTestCase(base.BaseTestCase):
    _mechanism_drivers = ['vpp']

    @mock.patch('networking_vpp.agent.server.vpp.VPPInterface.'
                'get_ifidx_by_name')
    @mock.patch('networking_vpp.agent.server.vpp.VPPInterface.'
                'get_ifidx_by_tag')
    @mock.patch('networking_vpp.agent.server.vpp')
    def setUp(self, m_vpp, m_vppifname, m_vppiftag):
        super(VPPForwarderTestCase, self).setUp()
        self.vpp = server.VPPForwarder({"test_net": "test_iface"})

        def idxes(iface):
            vals = {
                'test_iface': 720,
                'test_iface.1': 740
            }
            return vals.get(iface, None)
        self.vpp.vpp.get_ifidx_by_name.side_effect = idxes
        self.vpp.vpp.get_ifidx_by_tag.return_value = None

    def test_get_if_for_physnet(self):
        (ifname, ifidx) = self.vpp.get_if_for_physnet('test_net')
        self.vpp.vpp.get_ifidx_by_name.assert_called_once_with('test_iface')
        assert (ifname == 'test_iface'), 'test_net is on test_iface'
        assert (ifidx == 720), 'test_iface has idx 720'

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
        self.vpp.create_network_on_host('test_net', 'flat', '1')
        self.vpp.vpp.ifup.assert_called_once_with(720)
        self.vpp.vpp.add_to_bridge.called_once_with(5679, 720)
        assert (len(self.vpp.networks) == 1 + net_length), \
            "There should be one more network now"

    def test_vlan_create_network_on_host(self):
        net_length = len(self.vpp.networks)
        self.vpp.create_network_on_host('test_net', 'vlan', '1')
        self.vpp.vpp.ifup.assert_called_with(740)
        self.vpp.vpp.add_to_bridge.assert_called_once_with(740, 740)
        assert (len(self.vpp.networks) == 1 + net_length), \
            "There should be one more network now"

    def test_delete_network_on_host(self):
        physnet = 'test'
        self.vpp.networks = {(physnet, 'flat', None): {'bridge_domain_id': 1,
                                                       'network_type': 'flat'}}
        self.vpp.delete_network_on_host(physnet, 'flat')
        self.vpp.vpp.delete_bridge_domain.assert_called_once_with(1)

    @mock.patch('networking_vpp.agent.server.ip_lib')
    def test_bridge_exists_and_ensure_up(self, m_ip_lib):
        retval = self.vpp._bridge_exists_and_ensure_up('test')
        assert (retval is True), "Bridge link should have been found"

    @mock.patch('networking_vpp.agent.server.bridge_lib')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder._bridge_exists_and_ensure_up'
        )
    def test_ensure_bridge_found(self, m_br_ex, m_br_lib):
        m_br_ex.return_value = True
        self.vpp.ensure_bridge('test_ensure_br_f')
        assert m_br_lib.BridgeDevice.called_once_with('test_ensure_br_f')

    @mock.patch('networking_vpp.agent.server.bridge_lib')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder._bridge_exists_and_ensure_up'
        )
    def test_ensure_bridge(self, m_br_ex, m_br_lib):
        m_br_ex.return_value = False
        m_br_lib.BridgeDevice.setfd.return_value = False
        self.vpp.ensure_bridge('test_ensure_br')
        assert m_br_lib.BridgeDevice.addbr.called_once_with('test_ensure_br')

    @mock.patch('networking_vpp.agent.server.bridge_lib')
    @mock.patch('networking_vpp.agent.server.ip_lib')
    def test_add_external_tap(self, m_ip_lib, m_br_lib):
        m_ip_lib.device_exists.return_value = True
        device_name = "fake_dev"
        bridge = mock.MagicMock()
        bridge.owns_interface.return_value = False
        bridge_name = "fake_br"
        self.vpp.add_external_tap(device_name, bridge, bridge_name)
        bridge.addif.assert_called_once_with(device_name)

    def test_create_interface_on_host_exists(self):
        if_type = 'maketap'
        uuid = 'fakeuuid'
        mac = '00:00:00:00:00:00'
        fake_iface = {'bind_type': if_type,
                      'iface_idx': 1,
                      'mac': mac}
        self.vpp.interfaces = {uuid: fake_iface}
        retval = self.vpp.create_interface_on_host(if_type, uuid, mac)
        assert (retval == fake_iface)

    def test_create_interface_on_host_maketap(self):
        if_type = 'maketap'
        uuid = 'fakeuuid'
        mac = '00:00:00:00:00:00'
        retval = self.vpp.create_interface_on_host(if_type, uuid, mac)
        self.vpp.vpp.get_ifidx_by_tag.assert_called_once_with(uuid)
        self.vpp.vpp.create_tap.assert_called_once_with('tapfakeuuid',
                                                        mac, uuid)
        assert (retval == self.vpp.interfaces[uuid])

    @mock.patch('networking_vpp.agent.server.VPPForwarder.ensure_bridge')
    def test_create_interface_on_host_plugtap(self, m_en_br):
        if_type = 'plugtap'
        uuid = 'fakeuuid'
        mac = '00:00:00:00:00:00'
        retval = self.vpp.create_interface_on_host(if_type, uuid, mac)
        self.vpp.vpp.get_ifidx_by_tag.assert_called_once_with(uuid)
        self.vpp.vpp.create_tap.assert_called_once_with('vppfakeuuid',
                                                        mac, uuid)
        self.vpp.ensure_bridge.assert_called_once_with('br-fakeuuid')
        assert (retval == self.vpp.interfaces[uuid])

    def test_create_interface_on_host_vhostuser(self):
        if_type = 'vhostuser'
        uuid = 'fakeuuid'
        mac = '00:00:00:00:00:00'
        retval = self.vpp.create_interface_on_host(if_type, uuid, mac)
        self.vpp.vpp.get_ifidx_by_tag.assert_called_once_with(uuid)
        self.vpp.vpp.create_vhostuser.assert_called_once_with('/tmp/fakeuuid',
                                                              mac, uuid)
        assert (retval == self.vpp.interfaces[uuid])

    def test_create_interface_on_host_unsupported(self):
        if_type = 'unsupported'
        uuid = 'fakeuuid'
        mac = '00:00:00:00:00:00'
        self.assertRaises(server.UnsupportedInterfaceException,
                          self.vpp.create_interface_on_host,
                          if_type, uuid, mac)

    @mock.patch('networking_vpp.agent.server.VPPForwarder.network_on_host')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.create_interface_on_host')
    def test_bind_interface_on_host(self, m_create_iface_on_host,
                                    m_network_on_host):
        if_type = 'plugtap'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        physnet = 'fakenet'
        net_type = 'flat'
        seg_id = 1
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}
        m_create_iface_on_host.return_value = {'iface_idx': 'fakeidx'}
        expected_val = {'iface_idx': 'fakeidx',
                        'net_data': {'bridge_domain_id': 'fake_dom_id'}}
        retval = self.vpp.bind_interface_on_host(if_type,
                                                 uuid, mac, physnet,
                                                 net_type, seg_id)
        assert (retval == expected_val)

    def test_unbind_interface_on_host(self):
        pass
