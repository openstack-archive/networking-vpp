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
from mock import patch
import sys
import uuid as uuidgen
sys.modules['vpp_papi'] = mock.MagicMock()
sys.modules['vpp'] = mock.MagicMock()
sys.modules['threading'] = mock.MagicMock()
from ipaddress import ip_address
from networking_vpp.agent import server
from networking_vpp.mech_vpp import SecurityGroupRule
from neutron.tests import base

INTERNAL_SEGMENATION_ID = 100
INTERNAL_SEGMENATION_TYPE = 'vlan'
INTERNAL_PHYSNET = 'physnet1'
FIXED_IP_ADDRESS = '192.168.100.10'


class VPPForwarderTestCase(base.BaseTestCase):
    _mechanism_drivers = ['vpp']

    @mock.patch('networking_vpp.agent.server.vpp.VPPInterface.'
                'get_ifidx_by_tag')
    @mock.patch('networking_vpp.agent.server.vpp.VPPInterface.'
                'get_ifidx_by_name')
    @mock.patch('networking_vpp.agent.server.vpp')
    def setUp(self, m_vpp, m_vppif, m_vppif2):
        super(VPPForwarderTestCase, self).setUp()
        # Set mac timeout to 180s
        # TAP wait timeout does not need to be 60s, set it to 6s, as this may
        # speed up the test
        physnets = {"test_net": "test_iface"}
        self.vpp = server.VPPForwarder(physnets, 180, 6)
        self.etcd_listener = server.EtcdListener("test-host",
                                                 mock.MagicMock(),
                                                 self.vpp,
                                                 physnets)

        def idxes(iface):
            vals = {
                'test_iface': 720,
            }
            return vals[iface]

        def subif_idxes(iface, tag):
            vals = {
                ('test_iface.1'): 740,
                ('test_iface.100'): 5
            }
            return vals[iface + '.' + str(tag)]
        self.vpp.vpp.get_ifidx_by_name.side_effect = idxes
        self.vpp.vpp.get_ifidx_by_tag.return_value = None
        self.vpp.vpp.get_vlan_subif.side_effect = subif_idxes

    def test_interface_tag_len(self):
        uuid = uuidgen.uuid1()
        self.assertLessEqual(len(server.port_tag(uuid)), 64, 'Overlong tag')

    def test_uplink_tag_len(self):
        longest_physnet = '1234567890123456789012'
        self.assertLessEqual(
            len(server.uplink_tag(longest_physnet, 'flat', None)), 64,
            'Overlong flag net tag')
        max_vlan_id = 4095
        self.assertLessEqual(
            len(server.uplink_tag(longest_physnet, 'vlan', max_vlan_id)), 64,
            'Overlong vlan uplink tag')
        max_vxlan_id = 16777215
        self.assertLessEqual(
            len(server.uplink_tag(longest_physnet, 'vxlan', max_vxlan_id)), 64,
            'Overlong vxlan uplink tag')

    def test_decode_port_tag(self):
        uuid = uuidgen.uuid1()
        r = server.decode_port_tag(server.TAG_L2IFACE_PREFIX + str(uuid))
        self.assertEqual(str(uuid), r)

    def test_no_decode_port_tag(self):
        uuid = 'baduuid'
        r = server.decode_port_tag(server.TAG_L2IFACE_PREFIX + str(uuid))
        self.assertIsNone(r)

    def test_get_if_for_physnet(self):
        (ifname, ifidx) = self.vpp.get_if_for_physnet('test_net')
        self.vpp.vpp.get_ifidx_by_name.assert_called_once_with('test_iface')
        self.assertEqual(ifname, 'test_iface')
        self.assertEqual(ifidx, 720)

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_in_vpp')
    def test_no_network_on_host(self, m_ensure_network_in_vpp):
        physnet = 'test'
        self.vpp.ensure_network_on_host(physnet, 'flat', 0)
        m_ensure_network_in_vpp.assert_called_once_with(physnet, 'flat', 0)

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_in_vpp')
    def test_yes_network_on_host(self, m_ensure_network_in_vpp):
        physnet = 'test'
        self.vpp.networks = {(physnet, 'flat', 0): 'test'}
        retval = self.vpp.ensure_network_on_host(physnet, 'flat', 0)
        self.assertEqual(retval, 'test')
        m_ensure_network_in_vpp.assert_not_called()

    def test_none_ensure_network_on_host(self):
        retval = self.vpp.ensure_network_on_host('not_there', 'flat', None)
        self.assertIsNone(retval)

    def test_flat_ensure_network_on_host(self):
        net_length = len(self.vpp.networks)
        self.vpp.ensure_network_on_host('test_net', 'flat', '0')
        self.vpp.vpp.ifup.assert_called_once_with(720)
        # Flat networks should tag with just the physnet mark
        self.vpp.vpp.set_interface_tag.assert_called_once_with(
            720, 'net-vpp.physnet:test_net')
        self.vpp.vpp.create_bridge_domain.assert_called_once_with(720, 180)
        self.vpp.vpp.add_to_bridge.assert_called_once_with(720, 720)
        self.assertEqual(len(self.vpp.networks), 1 + net_length)

    def test_vlan_ensure_network_on_host(self):
        net_length = len(self.vpp.networks)
        self.vpp.ensure_network_on_host('test_net', 'vlan', '1')
        self.vpp.vpp.ifup.assert_called_with(740)
        # This will tag the physnet interface and the network uplink.
        self.assertEqual(
            sorted([mock.call(740, 'net-vpp.uplink:test_net.vlan.1'),
                    mock.call(720, 'net-vpp.physnet:test_net')]),
            sorted(self.vpp.vpp.set_interface_tag.mock_calls))
        self.vpp.vpp.create_bridge_domain.assert_called_once_with(740, 180)
        self.vpp.vpp.add_to_bridge.assert_called_once_with(740, 740)
        self.assertEqual(len(self.vpp.networks), 1 + net_length)

    def test_delete_network_on_host(self):
        physnet = 'test'
        self.vpp.networks = {(physnet, 'flat', None): {'bridge_domain_id': 1,
                                                       'if_physnet': 'physint',
                                                       'network_type': 'flat'}}
        self.vpp.vpp.get_bridge_domains.return_value = {1: []}

        self.vpp.delete_network_on_host(physnet, 'flat')

        self.vpp.vpp.delete_bridge_domain.assert_called_once_with(1)

    def test_delete_network_on_host_nobridge(self):
        physnet = 'test'
        self.vpp.networks = {(physnet, 'flat', None): {'bridge_domain_id': 1,
                                                       'if_physnet': 'physint',
                                                       'network_type': 'flat'}}
        self.vpp.vpp.get_bridge_domains.return_value = {}

        self.vpp.delete_network_on_host(physnet, 'flat')

        assert not self.vpp.vpp.delete_bridge_domain.called, \
            'delete_bridge_domain should not have been called'

    @mock.patch('networking_vpp.agent.server.ip_lib')
    def test_bridge_exists_and_ensure_up(self, m_ip_lib):
        retval = self.vpp._bridge_exists_and_ensure_up('test')
        self.assertTrue(retval)

    @mock.patch('networking_vpp.agent.server.bridge_lib')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder._bridge_exists_and_ensure_up'
        )
    def test_ensure_kernel_bridge_found(self, m_br_ex, m_br_lib):
        m_br_ex.return_value = True
        self.vpp.ensure_kernel_bridge('test_ensure_br_f')
        assert m_br_lib.BridgeDevice.called_once_with('test_ensure_br_f')

    @mock.patch('networking_vpp.agent.server.bridge_lib')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder._bridge_exists_and_ensure_up'
        )
    def test_ensure_kernel_bridge(self, m_br_ex, m_br_lib):
        m_br_ex.return_value = False
        m_br_lib.BridgeDevice.setfd.return_value = False
        self.vpp.ensure_kernel_bridge('test_ensure_br')
        assert m_br_lib.BridgeDevice.addbr.called_once_with('test_ensure_br')

    @mock.patch('networking_vpp.agent.server.bridge_lib')
    @mock.patch('networking_vpp.agent.server.ip_lib')
    def test_ensure_tap_in_bridge(self, m_ip_lib, m_br_lib):
        m_ip_lib.device_exists.return_value = True
        device_name = "fake_dev"

        bridge = mock.MagicMock()
        bridge.exists = mock.Mock(return_value=True)
        bridge.owns_interface = mock.Mock(return_value=False)
        m_br_lib.BridgeDevice.return_value = bridge
        bridge_name = "fake_br"
        self.vpp.ensure_tap_in_bridge(device_name, bridge_name)

        bridge.addif.assert_called_once_with(device_name)

    def test_ensure_interface_on_host_exists(self):
        if_type = 'tap'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        fake_iface = {'bind_type': if_type,
                      'iface_idx': 1,
                      'mac': mac}
        self.vpp.interfaces = {uuid: fake_iface}
        retval = self.vpp.ensure_interface_on_host(if_type, uuid, mac)
        self.assertEqual(retval, fake_iface)

    @mock.patch('networking_vpp.agent.server.'
                'VPPForwarder.ensure_kernel_bridge')
    def test_ensure_interface_on_host_tap(self, m_en_br):
        if_type = 'tap'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        expected_tag = 'net-vpp.port:' + uuid
        retval = self.vpp.ensure_interface_on_host(if_type, uuid, mac)
        self.vpp.vpp.create_tap.assert_called_once_with('vppfakeuuid',
                                                        mac,
                                                        expected_tag)
        self.vpp.ensure_kernel_bridge.assert_called_once_with('br-fakeuuid')
        self.assertEqual(retval, self.vpp.interfaces[uuid])

    def test_ensure_interface_on_host_vhostuser(self):
        if_type = 'vhostuser'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        expected_tag = 'net-vpp.port:' + uuid
        retval = self.vpp.ensure_interface_on_host(if_type, uuid, mac)
        self.vpp.vpp.create_vhostuser.assert_called_once_with('/tmp/fakeuuid',
                                                              mac,
                                                              expected_tag)
        self.assertEqual(retval, self.vpp.interfaces[uuid])

    def test_ensure_interface_on_host_unsupported(self):
        if_type = 'unsupported'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        self.vpp.interfaces = {}
        self.assertRaises(server.UnsupportedInterfaceException,
                          self.vpp.ensure_interface_on_host,
                          if_type, uuid, mac)

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_interface_on_host')
    def test_bind_interface_on_host(self, m_create_iface_on_host,
                                    m_network_on_host):
        if_type = 'tap'
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
        self.assertEqual(retval, expected_val)

    def _get_mock_router(self):
        # Return a mock router with a gateway
        return {'external_physnet': 'physnet1', 'external_net_type': 'vlan',
                'external_segment': 100, 'vrf_id': 5,
                'gateways': [('50.0.0.3', 24)]}

    def _get_mock_external_router(self):
        # Return a mock router with a gateway
        return {"status": "ACTIVE",
                'external_physnet': 'physnet1',
                'external_net_type': 'vlan',
                "external_segmentation_id": 100,
                'vrf_id': 5,
                "external_gateway_ip": "192.168.200.200",
                "gw_port_id": "dc717009-489d-4f53-9e40-d346e1962d8d",
                'gateways': [('50.0.0.3', 24, False)],
                "loopback_mac": "fa:16:3e:26:3e:7b",
                "mtu": 1500,
                "external_gateway_info":
                    {"network_id": "ecf2ff04-eb05-404a-a832-c2b8a8d33091",
                     "enable_snat": True,
                     "external_fixed_ips": [
                         {"subnet_id": "f4c1e37f-e5fe-474c-b2b6-ea0349b848e8",
                          "ip_address": "192.168.200.7"}]},
                }

    def _get_mock_router_interface(self):
        # Return a mock IPv4 internal router interface.
        return {'physnet': 'physnet1', 'net_type': 'vlan', 'vrf_id': 5,
                'segmentation_id': 100, 'mac_address': 'aa:bb:cc:dd:ee:ff',
                'gateway_ip': '10.0.0.1', 'is_ipv6': False, 'prefixlen': 24,
                'mtu': 1500, 'bridge_domain_id': 5, 'is_inside': True,
                'external_gateway_ip': None, 'uplink_idx': 5,
                'bvi_if_idx': 5, 'loopback_mac': 'aa:bb:cc:dd:ee:ff'}

    def _get_mock_router_external_interface(self):
        # Return a mock IPv4 External gateway router interface.
        return {'physnet': 'physnet1', 'net_type': 'vlan', 'vrf_id': 5,
                'segmentation_id': 100, 'mac_address': 'aa:bb:cc:dd:ee:ff',
                'gateway_ip': '10.0.0.1', 'is_ipv6': False, 'prefixlen': 24,
                'mtu': 1500, 'bridge_domain_id': 5, 'is_inside': False,
                'external_gateway_ip': '10.1.1.200', 'uplink_idx': 5,
                'bvi_if_idx': 5, 'loopback_mac': 'aa:bb:cc:dd:ee:ff'}

    def _get_mock_v6_router_interface(self):
        # Returns a mock IPv6 internal router interface.
        return {'physnet': 'physnet1', 'net_type': 'vlan', 'vrf_id': 5,
                'segmentation_id': 100, 'mac_address': 'aa:bb:cc:dd:ee:ff',
                'gateway_ip': '2001:db8:1234::1', 'is_ipv6': True,
                'prefixlen': 64, 'mtu': 1500, 'bridge_domain_id': 5,
                'is_inside': True, 'external_gateway_ip': None,
                'uplink_idx': 5, 'bvi_if_idx': 5,
                'loopback_mac': 'aa:bb:cc:dd:ee:ff'}

    def _get_mock_v6_router_external_interface(self):
        # Returns a mock IPv6 External Router interface.
        return {'physnet': 'physnet1', 'net_type': 'vlan', 'vrf_id': 5,
                'segmentation_id': 100, 'mac_address': 'aa:bb:cc:dd:ee:ff',
                'gateway_ip': '2001:db8:1234::1', 'is_ipv6': True,
                'prefixlen': 64, 'mtu': 1500, 'bridge_domain_id': 5,
                'is_inside': False, 'external_gateway_ip': '2001:db8:1234::f',
                'uplink_idx': 5, 'bvi_if_idx': 5,
                'loopback_mac': 'aa:bb:cc:dd:ee:ff'}

    def _get_mock_floatingip(self):
        return {'internal_segmentation_id': INTERNAL_SEGMENATION_ID,
                'internal_net_type': INTERNAL_SEGMENATION_TYPE,
                'internal_physnet': INTERNAL_PHYSNET,
                'external_segmentation_id': 172,
                'external_net_type': 'vlan',
                'external_physnet': 'testnet',
                'fixed_ip_address': FIXED_IP_ADDRESS,
                'floating_ip_address': '100.38.15.131'}

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def _test_create_router_interface_on_host(self, m_network_on_host,
                                              port, router):
        # Test adding an interface to the router to create it in VPP.
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}

        with mock.patch.object(self.vpp.vpp, 'get_bridge_bvi',
                               return_value=False):
            loopback_idx = self.vpp.ensure_router_interface_on_host(
                port, router)
            self.vpp.vpp.create_loopback.assert_called_once_with(
                router['mac_address'])
            self.vpp.vpp.set_loopback_bridge_bvi.assert_called_once_with(
                loopback_idx, 'fake_dom_id')
            self.vpp.vpp.set_interface_vrf.assert_called_once_with(
                loopback_idx, router['vrf_id'], router['is_ipv6'])
            self.vpp.vpp.set_interface_ip.assert_called_once_with(
                loopback_idx, self.vpp._pack_address(router['gateway_ip']),
                router['prefixlen'], router['is_ipv6'])

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def _test_create_router_interface_with_existing_bvi_and_ip(
        self, m_network_on_host, port, router):
        # Test repeat adding the same router interface.
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}

        with mock.patch.object(self.vpp.vpp, 'get_bridge_bvi',
                               return_value=5):
            with mock.patch.object(
                self.vpp.vpp, 'get_interface_ip_addresses',
                return_value=[(router['gateway_ip'], router['prefixlen'])]):
                self.vpp.ensure_router_interface_on_host(port, router)

                self.vpp.vpp.create_loopback.assert_not_called()
                self.vpp.vpp.set_loopback_bridge_bvi.assert_not_called()
                self.vpp.vpp.set_interface_vrf.assert_not_called()
                self.vpp.vpp.set_interface_ip.assert_not_called()

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def _test_create_router_interface_with_existing_bvi_different_ip(
        self, m_network_on_host, port, router, other_router):
        # Test adding a different router interface.
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}

        with mock.patch.object(self.vpp.vpp, 'get_bridge_bvi',
                               return_value=5):
            with mock.patch.object(
                self.vpp.vpp, 'get_interface_ip_addresses',
                return_value=[]):
                self.vpp.ensure_router_interface_on_host(port, router)

                self.vpp.vpp.create_loopback.assert_not_called()
                self.vpp.vpp.set_loopback_bridge_bvi.assert_not_called()
                self.vpp.vpp.set_interface_vrf.assert_not_called()
                self.vpp.vpp.set_interface_ip.assert_called_once_with(
                    5, self.vpp._pack_address(router['gateway_ip']),
                    router['prefixlen'], router['is_ipv6'])

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.' +
        'export_routes_from_tenant_vrfs')
    def _test_delete_router_interface_on_host(self, m_export_routes,
                                              m_network_on_host, port,
                                              is_ipv6):
        # Test deleting a router interface to delete the router in VPP.
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}
        if not is_ipv6:
            router_port = self._get_mock_router_interface()
        else:
            router_port = self._get_mock_v6_router_interface()
        self.vpp.router_interfaces[port] = router_port
        gateway_ip = router_port['gateway_ip']
        prefixlen = router_port['prefixlen']
        self.vpp.vpp.get_snat_interfaces.return_value = [5]
        self.vpp.vpp.get_bridge_bvi.return_value = 5
        self.vpp.vpp.get_interface_ip_addresses.return_value = [(gateway_ip,
                                                                prefixlen)]
        self.vpp.delete_router_interface_on_host(port)
        self.vpp.vpp.set_snat_on_interface.assert_called_once_with(
            5, is_add=False, is_inside=True)
        m_export_routes.assert_called_once_with(source_vrf=5, is_add=False)
        self.vpp.vpp.get_bridge_bvi.assert_called_once_with(5)
        self.vpp.vpp.delete_loopback.assert_called_once_with(5)
        self.assertEqual(
            self.vpp.router_interfaces.get(port), None
            )

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def _test_delete_router_interface_with_multiple_interfaces(
        self, m_network_on_host, port, is_ipv6):
        # Test deleting a router interface with interfaces from other subnets
        # also present on the router.
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}
        if not is_ipv6:
            router_port = self._get_mock_router_interface()
        else:
            router_port = self._get_mock_v6_router_interface()
        self.vpp.router_interfaces[port] = router_port
        gateway_ip = router_port['gateway_ip']
        prefixlen = router_port['prefixlen']
        second_gateway_ip = '2.2.2.2' if not is_ipv6 else 'ff0e::1001'
        second_gateway_prefixlen = 24
        self.vpp.vpp.get_snat_interfaces.return_value = [5]
        self.vpp.vpp.get_bridge_bvi.return_value = 5
        self.vpp.vpp.get_interface_ip_addresses.return_value = [
            (gateway_ip, prefixlen), (second_gateway_ip,
                                      second_gateway_prefixlen)]

        self.vpp.delete_router_interface_on_host(port)
        self.vpp.vpp.delete_loopback.assert_not_called()
        self.vpp.vpp.del_interface_ip.assert_called_once_with(
            5, self.vpp._pack_address(gateway_ip),
            prefixlen, router_port['is_ipv6'])

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def test_create_router_external_gateway_on_host(self, m_network_on_host):
        router = self._get_mock_external_router()
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}
        with mock.patch.object(self.vpp.vpp, 'get_bridge_bvi',
                               return_value=5):
            with mock.patch.object(self.vpp.vpp, 'get_snat_interfaces',
                                   return_value=[]):
                self.vpp.ensure_router_interface_on_host(
                    uuidgen.uuid1(), router)
                self.vpp.vpp.snat_overload_on_interface_address.\
                    assert_called_once_with(5)
                self.vpp.vpp.set_snat_on_interface.assert_called_once_with(
                    5, 0)
                self.vpp.vpp.set_interface_ip.assert_called_once_with(
                    5, self.vpp._pack_address(router['gateways'][0][0]),
                    router['gateways'][0][1], router['gateways'][0][2])

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def test_create_router_external_gateway_with_snat_interface_set(
            self, m_network_on_host):
        router = self._get_mock_external_router()
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}
        with mock.patch.object(self.vpp.vpp, 'get_bridge_bvi',
                               return_value=5):
            with mock.patch.object(self.vpp.vpp, 'get_snat_interfaces',
                                   return_value=[5]):
                self.vpp.ensure_router_interface_on_host(
                    uuidgen.uuid1(), router)
                self.vpp.vpp.set_snat_on_interface.assert_not_called()
                self.vpp.vpp.set_interface_ip.assert_called_once_with(
                    5, self.vpp._pack_address(router['gateways'][0][0]),
                    router['gateways'][0][1], router['gateways'][0][2])

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def test_create_router_external_gateway_with_snat_int_and_ip_set(
            self, m_network_on_host):
        router = self._get_mock_external_router()
        interface_ip = router['gateways'][0][0]
        prefixlen = router['gateways'][0][1]
        is_ipv6 = router['gateways'][0][2]
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}
        with mock.patch.object(self.vpp.vpp, 'get_bridge_bvi',
                               return_value=5):
            with mock.patch.object(self.vpp.vpp, 'get_snat_interfaces',
                                   return_value=[5]):
                with mock.patch.object(
                    self.vpp.vpp, 'get_interface_ip_addresses',
                    return_value=[]):
                    self.vpp.ensure_router_interface_on_host(
                        uuidgen.uuid1(), router)
                    self.vpp.vpp.set_snat_on_interface.assert_not_called()
                    self.vpp.vpp.set_interface_ip.assert_called_once_with(
                        5, self.vpp._pack_address(interface_ip),
                        prefixlen, is_ipv6)

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def test_create_router_external_gateway_snat_int_ip_and_ext_gw_set(
            self, m_network_on_host):
        router = self._get_mock_external_router()
        interface_ip = router['gateways'][0][0]
        prefixlen = router['gateways'][0][1]
        m_network_on_host.return_value = {'bridge_domain_id': 'fake_dom_id'}
        with mock.patch.object(self.vpp.vpp, 'get_bridge_bvi',
                               return_value=5):
            with mock.patch.object(self.vpp.vpp, 'get_snat_interfaces',
                                   return_value=[5]):
                    with mock.patch.object(
                        self.vpp.vpp, 'get_interface_ip_addresses',
                        return_value=[(interface_ip, prefixlen)]):
                        self.vpp.ensure_router_interface_on_host(
                            uuidgen.uuid1(), router)
                        self.vpp.vpp.set_snat_on_interface.assert_not_called()
                        self.vpp.vpp.set_interface_ip.assert_not_called()

    def test_delete_router_external_gateway_on_host(self):
        router_port = self._get_mock_router_external_interface()
        port_id = uuidgen.uuid1()
        self.vpp.router_external_interfaces[port_id] = router_port
        with mock.patch.object(self.vpp.vpp, 'get_snat_interfaces',
                               return_value=[router_port['bvi_if_idx']]):
            with mock.patch.object(self.vpp.vpp,
                                   'get_outside_snat_interface_indices',
                                   return_value=[router_port['bvi_if_idx']]):
                with mock.patch.object(self.vpp.vpp,
                                       'get_interface_ip_addresses',
                                       return_value=[
                                           (router_port['gateway_ip'],
                                            router_port['prefixlen'])]):
                    with mock.patch.object(self.vpp.vpp,
                                           'get_bridge_bvi',
                                           return_value=router_port[
                                               'bvi_if_idx']):
                        self.vpp.delete_router_interface_on_host(port_id)
                        self.vpp.vpp.set_snat_on_interface.\
                            assert_called_once_with(router_port['bvi_if_idx'],
                                                    is_inside=False,
                                                    is_add=False)
                        self.vpp.vpp.snat_overload_on_interface_address.\
                            assert_called_once_with(router_port['bvi_if_idx'],
                                                    is_add=False)
                        self.vpp.vpp.delete_loopback.assert_called_once_with(
                            router_port['bvi_if_idx'])

    def test_delete_router_external_gateway_no_snat_addr(self):
        router_port = self._get_mock_router_external_interface()
        port_id = uuidgen.uuid1()
        self.vpp.router_external_interfaces[port_id] = router_port
        with mock.patch.object(self.vpp.vpp, 'get_snat_interfaces',
                               return_value=[]):
            with mock.patch.object(self.vpp.vpp,
                                   'get_outside_snat_interface_indices',
                                   return_value=[]):
                with mock.patch.object(
                    self.vpp.vpp, 'get_bridge_bvi',
                    return_value=router_port['bvi_if_idx']):
                    with mock.patch.object(
                        self.vpp.vpp, 'get_interface_ip_addresses',
                        return_value=[(router_port['gateway_ip'],
                                       router_port['prefixlen'])]):
                        self.vpp.delete_router_interface_on_host(port_id)
                        self.vpp.vpp.set_snat_on_interface.\
                            assert_not_called()
                        self.vpp.vpp.snat_overload_on_interface_address.\
                            assert_not_called()
                        self.vpp.vpp.delete_loopback.assert_called_once_with(
                            router_port['bvi_if_idx'])

    def test_delete_router_external_gateway_no_snat_addr_and_no_ext_gw(self):
        router_port = self._get_mock_router_external_interface()
        port_id = uuidgen.uuid1()
        self.vpp.router_external_interfaces[port_id] = router_port
        with mock.patch.object(self.vpp.vpp, 'get_snat_interfaces',
                               return_value=[]):
            with mock.patch.object(self.vpp.vpp,
                                   'get_outside_snat_interface_indices',
                                   return_value=[]):
                with mock.patch.object(self.vpp.vpp,
                                       'get_bridge_bvi', return_value=None):
                    with mock.patch.object(
                        self.vpp.vpp, 'get_interface_ip_addresses',
                        return_value=[]):
                        self.vpp.delete_router_interface_on_host(port_id)
                        self.vpp.vpp.set_snat_on_interface.\
                            assert_not_called()
                        self.vpp.vpp.snat_overload_on_interface_address.\
                            assert_not_called()
                        self.vpp.vpp.delete_loopback.assert_not_called()

    def test_v4_router_interface_create_on_host(self):
        self._test_create_router_interface_on_host(
            port=uuidgen.uuid1(),
            router=self._get_mock_router_interface())

    def test_v6_router_interface_create_on_host(self):
        self._test_create_router_interface_on_host(
            port=uuidgen.uuid1(),
            router=self._get_mock_v6_router_interface())

    def test_v4_router_interface_create_with_existing_bvi_and_ip(self):
        self._test_create_router_interface_with_existing_bvi_and_ip(
            port=uuidgen.uuid1(),
            router=self._get_mock_router_interface())

    def test_v6_router_interface_create_with_existing_bvi_and_ip(self):
        self._test_create_router_interface_with_existing_bvi_and_ip(
            port=uuidgen.uuid1(),
            router=self._get_mock_v6_router_interface())

    def test_v4_router_interface_create_with_existing_bvi_different_ip(self):
        self._test_create_router_interface_with_existing_bvi_different_ip(
            port=uuidgen.uuid1(),
            router=self._get_mock_router_interface(),
            other_router=self._get_mock_v6_router_interface())

    def test_v6_router_interface_create_with_existing_bvi_different_ip(self):
        self._test_create_router_interface_with_existing_bvi_different_ip(
            port=uuidgen.uuid1(),
            router=self._get_mock_v6_router_interface(),
            other_router=self._get_mock_router_interface())

    def test_v4_router_interface_delete(self):
        self._test_delete_router_interface_on_host(
            port=uuidgen.uuid1(), is_ipv6=False)

    def test_v6_router_interface_delete(self):
        self._test_delete_router_interface_on_host(
            port=uuidgen.uuid1(), is_ipv6=True)

    def test_v4_router_interface_delete_with_multiple_interfaces(self):
        self._test_delete_router_interface_with_multiple_interfaces(
            port=uuidgen.uuid1(), is_ipv6=False)

    def test_v6_router_interface_delete_with_multiple_interfaces(self):
        self._test_delete_router_interface_with_multiple_interfaces(
            port=uuidgen.uuid1(), is_ipv6=True)

    def test_create_floatingip_on_vpp(self):
        """Test create floatingip processing.

        Verify that the SNAT create APIs are called.
        """
        floatingip_dict = self._get_mock_floatingip()
        self.vpp.vpp.get_snat_interfaces.return_value = []
        mock.patch.object(self.vpp, '_get_snat_indexes',
                          return_value=(2, 3)).start()
        self.vpp.associate_floatingip(floatingip_dict['floating_ip_address'],
                                      floatingip_dict)

        self.assertEqual(self.vpp.vpp.set_snat_on_interface.call_count, 2)
        self.vpp.vpp.set_snat_static_mapping.assert_called_once_with(
            floatingip_dict['fixed_ip_address'],
            floatingip_dict['floating_ip_address'])

    def test_create_floatingip_on_vpp_existing_entry(self):
        """Test create floatingip processing with existing indexes.

        Verify that the SNAT interfaces are not created if they already
        exist on the VPP.
        """
        floatingip_dict = self._get_mock_floatingip()
        self.vpp.vpp.get_snat_interfaces.return_value = [4, 5]
        mock.patch.object(self.vpp, '_get_snat_indexes',
                          return_value=(4, 5)).start()
        self.vpp.vpp.get_snat_local_ipaddresses.return_value = (
            [floatingip_dict['fixed_ip_address']])

        self.vpp.associate_floatingip(floatingip_dict['floating_ip_address'],
                                      floatingip_dict)

        self.assertFalse(self.vpp.vpp.set_snat_on_interface.call_count)
        self.assertFalse(self.vpp.vpp.set_snat_static_mapping.call_count)

    def test_create_floatingip_on_vpp_no_internal_network(self):
        """Test create floatingip processing without an internal network.

        Verify that the SNAT interfaces are not created when the
        internal network (router interface) hasn't been created.
        """
        floatingip_dict = self._get_mock_floatingip()

        self.vpp.associate_floatingip(floatingip_dict['floating_ip_address'],
                                      floatingip_dict)

        self.assertFalse(self.vpp.vpp.set_snat_on_interface.call_count)

    def test_delete_floatingip_on_vpp(self):
        """Test delete floatingip processing.

        Verify that the SNAT delete APIs are called.
        """
        floatingip_dict = self._get_mock_floatingip()
        floating_ip = floatingip_dict['floating_ip_address']
        self.vpp.floating_ips[floating_ip] = floatingip_dict
        self.vpp.vpp.get_snat_local_ipaddresses.return_value = [
            floatingip_dict['fixed_ip_address']]

        self.vpp.disassociate_floatingip(floating_ip)

        self.vpp.vpp.set_snat_static_mapping.assert_called_once_with(
            floatingip_dict['fixed_ip_address'],
            floatingip_dict['floating_ip_address'],
            is_add=0)
        self.assertEqual(
            self.vpp.floating_ips.get(floating_ip), None
            )

    def test_delete_floatingip_on_vpp_non_existing(self):
        """Test delete a non-exisiting floatingip within VPP.

        Verify that a SNAT delete operation is not performed.
        """
        floatingip_dict = self._get_mock_floatingip()
        floating_ip = floatingip_dict['floating_ip_address']
        self.vpp.floating_ips[floating_ip] = floatingip_dict
        self.vpp.vpp.get_snat_local_ipaddresses.return_value = []

        self.vpp.disassociate_floatingip(floating_ip)

        self.vpp.vpp.set_snat_static_mapping.assert_not_called()
        self.assertEqual(
            self.vpp.floating_ips.get(floating_ip), None
            )

    def test_ensure_gpe_network_on_host(self):
        self.vpp.networks = {}
        self.vpp.mac_age = 300
        self.vpp.gpe_locators = "uplink"
        physnet, net_type, seg_id = 'uplink', 'vxlan', 5000
        self.vpp.physnets = {"uplink": "test_iface"}
        self.vpp.gpe_src_cidr = "10.1.1.1/24"
        self.vpp.vpp.get_bridge_domains.return_value = []
        self.vpp.vpp.get_lisp_vni_to_bd_mappings.return_value = []
        ret_val = self.vpp.ensure_network_on_host(physnet, net_type, seg_id)
        self.vpp.vpp.create_bridge_domain.assert_called_once_with(
            70000, 300)
        self.vpp.vpp.add_lisp_vni_to_bd_mapping.assert_called_once_with(
            vni=5000, bridge_domain=70000)
        self.vpp.vpp.set_interface_address.assert_called_once_with(
            sw_if_index=720, is_ipv6=0,
            address_length=24, address=self.vpp._pack_address("10.1.1.1"))
        self.vpp.vpp.set_interface_tag.assert_called_with(
            720, 'net-vpp.physnet:uplink')
        network_data = self.vpp.networks[('uplink', 'vxlan', 5000)]
        expected_val = {'bridge_domain_id': 70000,
                        'if_physnet': "test_iface",
                        'network_type': 'vxlan',
                        'segmentation_id': 5000,
                        'physnet': 'uplink'}
        self.assertEqual(network_data, expected_val)
        self.assertEqual(ret_val, expected_val)

    def test_delete_gpe_network_on_host(self):
        self.vpp.networks = {}
        self.vpp.gpe_map = {}
        gpe_lset_name = 'net-vpp-gpe-lset-1'
        self.vpp.gpe_locators = "uplink"
        self.vpp.physnets = {"uplink": "test_iface"}
        physnet, net_type, seg_id = 'uplink', 'vxlan', 5000
        mock_data = {'bridge_domain_id': 70000,
                     'if_physnet': "test_iface",
                     'if_uplink_idx': 720,
                     'network_type': 'vxlan',
                     'segmentation_id': 5000,
                     'physnet': "uplink"}
        mock_gpe_local_map_data = {'vnis': set([5000])}
        mock_gpe_remote_map_data = {('fake-mac1', 5000): 'fake-remote-ip1',
                                    ('fake-mac2', 5000): 'fake-remote-ip1',
                                    ('fake-mac3', 5001): 'fake-remote-ip2'
                                    }
        self.vpp.vpp.get_lisp_vni_to_bd_mappings.return_value = [(5000,
                                                                  70000)]
        self.vpp.gpe_map[gpe_lset_name] = mock_gpe_local_map_data
        self.vpp.gpe_map['remote_map'] = mock_gpe_remote_map_data
        self.vpp.networks[(physnet, net_type, seg_id)] = mock_data
        self.vpp.delete_network_on_host(physnet, net_type, seg_id)
        self.vpp.vpp.del_lisp_vni_to_bd_mapping.assert_called_once_with(
            vni=5000, bridge_domain=70000)
        self.assertEqual(self.vpp.gpe_map[gpe_lset_name]['vnis'], set([]))
        self.vpp.vpp.del_lisp_remote_mac.assert_any_call(
            'fake-mac1', 5000)
        self.vpp.vpp.del_lisp_remote_mac.assert_any_call(
            'fake-mac2', 5000)
        self.assertEqual(self.vpp.gpe_map['remote_map'], {
            ('fake-mac3', 5001): 'fake-remote-ip2'})
        self.assertEqual(self.vpp.networks, {})

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.' +
        'ensure_interface_in_vpp_bridge')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_interface_on_host')
    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_on_host')
    def test_bind_gpe_interface_on_host(self,
                                        mock_ensure_net_on_host,
                                        mock_ensure_int_on_host,
                                        mock_ensure_int_in_bridge):
        gpe_lset_name = 'net-vpp-gpe-lset-1'
        self.vpp.gpe_locators = "uplink"
        self.vpp.physnets = {"uplink": "test_iface"}
        mock_net_data = {'bridge_domain_id': 70000,
                         'if_physnet': "test_iface",
                         'if_uplink_idx': 720,
                         'network_type': 'vxlan',
                         'segmentation_id': 5000,
                         'physnet': 'uplink'}
        mock_props = {'iface_idx': 10,
                      'bind_type': 'vhostuser',
                      'mac': '11:11:11:11:11:11',
                      'path': '/tmp/fake-path'}
        mock_gpe_map = {'vnis': set([]),
                        'sw_if_idxs': set([]),
                        'local_map': {}}
        self.vpp.gpe_map[gpe_lset_name] = mock_gpe_map
        mock_ensure_net_on_host.return_value = mock_net_data
        mock_ensure_int_on_host.return_value = mock_props
        self.vpp.bind_interface_on_host('vhostuser', 'fake-uuid',
                                        mock_props['mac'], 'uplink', 'vxlan',
                                        5000)
        mock_ensure_int_in_bridge.assert_called_once_with(70000, 10)
        self.assertEqual(
            self.vpp.gpe_map[gpe_lset_name]['vnis'],
            set([5000]))
        self.vpp.vpp.add_lisp_local_mac.assert_called_once_with(
            mock_props['mac'], 5000, gpe_lset_name)
        self.assertEqual(
            self.vpp.gpe_map[gpe_lset_name]['local_map'][mock_props['mac']],
            5000)

    def test_unbind_gpe_interface_on_host(self):
        gpe_lset_name = 'net-vpp-gpe-lset-1'
        self.vpp.gpe_locators = "uplink"
        self.vpp.physnets = {"uplink": "test_iface"}
        port_uuid = 'fake-port-uuid'
        mock_net_data = {'bridge_domain_id': 70000,
                         'if_physnet': "test_iface",
                         'if_uplink_idx': 720,
                         'network_type': 'vxlan',
                         'segmentation_id': 5000,
                         'physnet': 'uplink'}
        mock_props = {'iface_idx': 10,
                      'bind_type': 'vhostuser',
                      'mac': '11:11:11:11:11:11',
                      'path': '/tmp/fake-path',
                      'net_data': mock_net_data}
        mock_gpe_map = {'vnis': set([5000]),
                        'sw_if_indxs': set([720]),
                        'local_map': {'11:11:11:11:11:11': 5000}
                        }
        self.vpp.vpp.get_lisp_vni_to_bd_mappings.return_value = [(5000,
                                                                  70000)]
        self.vpp.interfaces[port_uuid] = mock_props
        self.vpp.networks[('uplink', 'vxlan', 5000)] = mock_net_data
        self.vpp.gpe_map[gpe_lset_name] = mock_gpe_map
        self.vpp.gpe_map['remote_map'] = {}
        self.vpp.port_ips[port_uuid] = '1.1.1.1'
        # Nominates an empty bridge that must be deleted
        # We no longer delete bridges that don't exist
        self.vpp.vpp.get_bridge_domains.return_value = {70000: []}

        self.vpp.unbind_interface_on_host(port_uuid)

        self.vpp.vpp.del_lisp_local_mac.assert_called_once_with(
            mock_props['mac'],
            mock_net_data['segmentation_id'],
            gpe_lset_name)
        self.assertEqual(self.vpp.gpe_map[gpe_lset_name]['local_map'], {})
        self.assertEqual(self.vpp.interfaces, {})
        self.vpp.vpp.delete_bridge_domain.assert_called_once_with(
            mock_net_data['bridge_domain_id'])
        self.vpp.vpp.del_lisp_vni_to_bd_mapping.assert_called_once_with(
            vni=mock_net_data['segmentation_id'],
            bridge_domain=mock_net_data['bridge_domain_id'])
        self.assertEqual(self.vpp.gpe_map[gpe_lset_name]['vnis'], set([]))
        self.assertEqual(self.vpp.networks, {})

    @mock.patch('networking_vpp.agent.server.EtcdListener')
    def test_ensure_remote_gpe_mapping(self, mock_etcd_listener):
        """Test Adding remote GPE mappings.

        Patch the EtcdListener object in and create a mock GpeWatcher.
        Then simulate an mock_gpe_key add.
        Test the remote mapping and ARP entry modules
        """
        mock_gpe_key = "/networking-vpp/global/networks/gpe" + \
                       "/1077/ml-ucs-02/fa:16:3e:47:2e:3c/10.1.1.2"
        mock_remote_ip = "1.1.1.1"
        mock_bridge_domain = 66077
        with patch.object(server.GpeWatcher, 'added',
                          autospec=True) as mock_add_key:
            mock_etcd_client = mock.MagicMock()
            mock_etcd_listener.is_valid_remote_map.return_value = True
            mock_etcd_listener.vppf = self.vpp
            self.vpp.gpe_map = {'remote_map': {}}
            self.vpp.vpp.exists_lisp_arp_entry.return_value = False
            remote_locator = {"is_ip4": 1,
                              "priority": 1,
                              "weight": 1,
                              "addr": self.vpp._pack_address("1.1.1.1")
                              }
            server.GpeWatcher(mock_etcd_client,
                              'gpe_watcher',
                              mock_gpe_key,
                              mock_etcd_listener
                              ).added(mock_gpe_key,
                                      mock_remote_ip)
            mock_add_key.assert_called_once_with(mock.ANY,
                                                 mock_gpe_key,
                                                 mock_remote_ip)
            self.vpp.ensure_remote_gpe_mapping(1077, 'fa:16:3e:47:2e:3c',
                                               '10.1.1.2', '1.1.1.1')
            self.vpp.vpp.\
                add_lisp_remote_mac.assert_called_once_with(
                    'fa:16:3e:47:2e:3c', 1077, remote_locator)
            self.assertIn(('fa:16:3e:47:2e:3c', 1077),
                          self.vpp.gpe_map['remote_map'])
            self.assertEqual(
                self.vpp.gpe_map['remote_map'][('fa:16:3e:47:2e:3c', 1077)],
                "1.1.1.1")
            self.vpp.vpp.\
                add_lisp_arp_entry.assert_called_once_with(
                    'fa:16:3e:47:2e:3c', mock_bridge_domain,
                    int(ip_address(unicode('10.1.1.2'))))

    @mock.patch('networking_vpp.agent.server.EtcdListener')
    def test_delete_remote_gpe_mapping(self, mock_etcd_listener):
        """Test Deleting a remote GPE mapping.

        Patch the EtcdListener object in and create a mock GpeWatcher.
        Then simulate an mock_gpe_key delete.
        Test the remote mapping and ARP entry modules
        """
        mock_gpe_key = "/networking-vpp/global/networks/gpe" + \
                       "/1077/ml-ucs-02/fa:16:3e:47:2e:3c/10.1.1.2"
        mock_remote_ip = "1.1.1.1"
        mock_bridge_domain = 66077
        with patch.object(server.GpeWatcher, 'removed',
                          autospec=True) as mock_remove_key:
            mock_etcd_client = mock.MagicMock()
            mock_etcd_listener.is_valid_remote_map.return_value = True
            mock_etcd_listener.vppf = self.vpp
            self.vpp.gpe_map = {'remote_map': {
                                ('fa:16:3e:47:2e:3c', 1077): mock_remote_ip}}
            self.vpp.vpp.exists_lisp_arp_entry.return_value = True
            server.GpeWatcher(mock_etcd_client,
                              'gpe_watcher',
                              mock_gpe_key,
                              mock_etcd_listener
                              ).removed(mock_gpe_key)
            mock_remove_key.assert_called_once_with(mock.ANY,
                                                    mock_gpe_key)
            self.vpp.delete_remote_gpe_mapping(1077, 'fa:16:3e:47:2e:3c',
                                               '10.1.1.2')
            self.vpp.vpp.\
                del_lisp_remote_mac.assert_called_once_with(
                    'fa:16:3e:47:2e:3c', 1077)
            self.vpp.vpp.\
                del_lisp_arp_entry.assert_called_once_with(
                    'fa:16:3e:47:2e:3c', mock_bridge_domain,
                    int(ip_address(unicode('10.1.1.2'))))

    def test_replace_remote_gpe_arp_entry(self):
        """Test replacing a GPE ARP Entry.

        Mock add an ARP entry with an existing ARP entry for the same IP.
        Test if the ARP entry is replaced
        """
        mock_bridge_domain = 66077
        self.vpp.gpe_map = {'remote_map': {}}
        self.vpp.vpp.exists_lisp_arp_entry.return_value = True
        remote_locator = {"is_ip4": 1,
                          "priority": 1,
                          "weight": 1,
                          "addr": self.vpp._pack_address("1.1.1.1")
                          }
        self.vpp.ensure_remote_gpe_mapping(1077, 'fa:16:3e:47:2e:3c',
                                           '10.1.1.2', '1.1.1.1')
        self.vpp.vpp.\
            add_lisp_remote_mac.assert_called_once_with(
                'fa:16:3e:47:2e:3c', 1077, remote_locator)
        self.assertIn(('fa:16:3e:47:2e:3c', 1077),
                      self.vpp.gpe_map['remote_map'])
        self.assertEqual(
            self.vpp.gpe_map['remote_map'][('fa:16:3e:47:2e:3c', 1077)],
            "1.1.1.1")
        self.vpp.ensure_remote_gpe_mapping(1077, 'fa:16:3e:47:2e:3c',
                                           '10.1.1.2', '1.1.1.1')
        self.vpp.vpp.\
            replace_lisp_arp_entry.assert_called_once_with(
                'fa:16:3e:47:2e:3c', mock_bridge_domain,
                int(ip_address(unicode('10.1.1.2'))))

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.acl_add_replace_on_host')
    def test_acl_add_replace(self, mock_acl_add_replace):
        sec_group = "fake-secgroup"
        self.vpp.remote_group_ports["remote-group1"] = set(
            ["port1", "port2"])
        self.vpp.port_ips["port1"] = set(
            ["2001::1", "2001::2", "1.1.1.1"])
        self.vpp.port_ips["port2"] = set(
            ["2002::1", "2002::2", "2.2.2.2"])
        fake_rule_data = {
            "ingress_rules": [{
                "is_ipv6": 1,
                "remote_ip_addr": None,
                "ip_prefix_len": 0,
                "remote_group_id": "remote-group1",
                "protocol": 6,
                "port_min": 80,
                "port_max": 81
                },
                {
                "is_ipv6": 0,
                "remote_ip_addr": None,
                "ip_prefix_len": 0,
                "remote_group_id": "remote-group1",
                "protocol": 6,
                "port_min": 80,
                "port_max": 81
                },
                {"is_ipv6": 1,
                 "remote_ip_addr": "2001:aa12::",
                 "ip_prefix_len": 64,
                 "remote_group_id": None,
                 "protocol": 6,
                 "port_min": 8080,
                 "port_max": 8080}],
            "egress_rules": [{
                "is_ipv6": 1,
                "remote_ip_addr": None,
                "ip_prefix_len": 0,
                "remote_group_id": "remote-group1",
                "protocol": 6,
                "port_min": 443,
                "port_max": 1000}]
            }
        self.etcd_listener.acl_add_replace(sec_group, fake_rule_data)
        self.assertIn("fake-secgroup",
                      self.vpp.remote_group_secgroups["remote-group1"])
        # Compute ingress and egress rule products using the IP addresses
        # in the remote-group named remote-group1
        ingress_rules = [
            SecurityGroupRule(1, ip_address(u'2001::1').packed,
                              128, 'remote-group1', 6, 80, 81),
            SecurityGroupRule(1, ip_address(u'2001::2').packed,
                              128, 'remote-group1', 6, 80, 81),
            SecurityGroupRule(1, ip_address(u'2002::1').packed,
                              128, 'remote-group1', 6, 80, 81),
            SecurityGroupRule(1, ip_address(u'2002::2').packed,
                              128, 'remote-group1', 6, 80, 81),
            SecurityGroupRule(0, ip_address(u'1.1.1.1').packed,
                              32, 'remote-group1', 6, 80, 81),
            SecurityGroupRule(0, ip_address(u'2.2.2.2').packed,
                              32, 'remote-group1', 6, 80, 81),
            SecurityGroupRule(1, ip_address(u'2001:aa12::').packed,
                              64, None, 6, 8080, 8080),
            ]
        egress_rules = [
            SecurityGroupRule(1, ip_address(u'2001::1').packed,
                              128, 'remote-group1', 6, 443, 1000),
            SecurityGroupRule(1, ip_address(u'2001::2').packed,
                              128, 'remote-group1', 6, 443, 1000),
            SecurityGroupRule(1, ip_address(u'2002::1').packed,
                              128, 'remote-group1', 6, 443, 1000),
            SecurityGroupRule(1, ip_address(u'2002::2').packed,
                              128, 'remote-group1', 6, 443, 1000),
            ]
        (security_group, ) = mock_acl_add_replace.call_args[0]
        self.assertEqual(security_group.id, "fake-secgroup")
        self.assertEqual(set(security_group.ingress_rules), set(ingress_rules))
        self.assertEqual(set(security_group.egress_rules), set(egress_rules))
