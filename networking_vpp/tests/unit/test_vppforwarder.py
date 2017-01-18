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
import time
import uuid as uuidgen
sys.modules['vpp_papi'] = mock.MagicMock()
sys.modules['threading'] = mock.MagicMock()
from networking_vpp.agent import server
from neutron.tests import base


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
        self.vpp = server.VPPForwarder({"test_net": "test_iface"}, 180, 6)

        def idxes(iface):
            vals = {
                'test_iface': 720,
            }
            return vals[iface]

        def subif_idxes(iface, tag):
            vals = {
                ('test_iface.1'): 740
            }
            return vals[iface + '.' + str(tag)]
        self.vpp.vpp.get_ifidx_by_name.side_effect = idxes
        self.vpp.vpp.get_ifidx_by_tag.return_value = None
        self.vpp.vpp.get_vlan_subif.side_effect = subif_idxes

    def test_interface_tag_len(self):
        uuid = uuidgen.uuid1()
        assert (len(server.port_tag(uuid)) <= 64), 'TAG len must be <= 64'

    def test_uplink_tag_len(self):
        assert (len(server.uplink_tag('flat', 0)) <= 64), \
            'TAG len for flat networks  must be <= 64'
        max_vlan_id = 4095
        assert (len(server.uplink_tag('vlan', max_vlan_id)) <= 64), \
            'TAG len for vlan overlays must be <= 64'
        max_vxlan_id = 16777215
        assert (len(server.uplink_tag('vxlan', max_vxlan_id)) <= 64), \
            'TAG len for vxlan overlays must be <= 64'

    def test_decode_port_tag(self):
        uuid = uuidgen.uuid1()
        r = server.decode_port_tag(server.TAG_L2IFACE_PREFIX + str(uuid))
        assert (str(uuid) == r), "Expected '%s', got '%s'" % (str(uuid), r)

    def test_no_decode_port_tag(self):
        uuid = 'baduuid'
        r = server.decode_port_tag(server.TAG_L2IFACE_PREFIX + str(uuid))
        assert (r is None)

    def test_get_if_for_physnet(self):
        (ifname, ifidx) = self.vpp.get_if_for_physnet('test_net')
        self.vpp.vpp.get_ifidx_by_name.assert_called_once_with('test_iface')
        assert (ifname == 'test_iface'), 'test_net is on test_iface'
        assert (ifidx == 720), 'test_iface has idx 720'

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_in_vpp')
    def test_no_network_on_host(self, m_ensure_network_in_vpp):
        physnet = 'test'
        self.vpp.ensure_network_on_host(physnet, 'flat', 0)
        assert m_ensure_network_in_vpp.called_once_with(physnet, 'flat', 0)

    @mock.patch(
        'networking_vpp.agent.server.VPPForwarder.ensure_network_in_vpp')
    def test_yes_network_on_host(self, m_ensure_network_in_vpp):
        physnet = 'test'
        self.vpp.networks = {(physnet, 'flat', 0): 'test'}
        retval = self.vpp.ensure_network_on_host(physnet, 'flat', 0)
        assert(retval == 'test'), "Return network value should be 'test'"
        m_ensure_network_in_vpp.assert_not_called()

    def test_none_ensure_network_on_host(self):
        retval = self.vpp.ensure_network_on_host('not_there', 'flat', None)
        assert (retval is None), "Return value should have been None"

    def test_flat_ensure_network_on_host(self):
        net_length = len(self.vpp.networks)
        self.vpp.ensure_network_on_host('test_net', 'flat', '1')
        self.vpp.vpp.ifup.assert_called_once_with(720)
        self.vpp.vpp.set_interface_tag.assert_called_once_with(
            720,
            'net-vpp.uplink:flat.1')
        self.vpp.vpp.create_bridge_domain.assert_called_once_with(720, 180)
        self.vpp.vpp.add_to_bridge.assert_called_once_with(720, 720)
        assert (len(self.vpp.networks) == 1 + net_length), \
            "There should be one more network now"

    def test_vlan_ensure_network_on_host(self):
        net_length = len(self.vpp.networks)
        self.vpp.ensure_network_on_host('test_net', 'vlan', '1')
        self.vpp.vpp.ifup.assert_called_with(740)
        self.vpp.vpp.set_interface_tag.assert_called_once_with(
            740,
            'net-vpp.uplink:vlan.1')
        self.vpp.vpp.create_bridge_domain.assert_called_once_with(740, 180)
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
        # tap creation is done asynchronously, wait until the queue is empty
        while not self.vpp._external_taps.empty():
            time.sleep(2)
        bridge.addif.assert_called_once_with(device_name)

    def test_ensure_interface_on_host_exists(self):
        if_type = 'maketap'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        fake_iface = {'bind_type': if_type,
                      'iface_idx': 1,
                      'mac': mac}
        self.vpp.interfaces = {uuid: fake_iface}
        retval = self.vpp.ensure_interface_on_host(if_type, uuid, mac)
        assert (retval == fake_iface)

    def test_ensure_interface_on_host_maketap(self):
        if_type = 'maketap'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        expected_tag = 'net-vpp.port:' + uuid
        retval = self.vpp.ensure_interface_on_host(if_type, uuid, mac)
        self.vpp.vpp.create_tap.assert_called_once_with('tapfakeuuid',
                                                        mac,
                                                        expected_tag)
        assert (retval == self.vpp.interfaces[uuid])

    @mock.patch('networking_vpp.agent.server.VPPForwarder.ensure_bridge')
    def test_ensure_interface_on_host_plugtap(self, m_en_br):
        if_type = 'plugtap'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        expected_tag = 'net-vpp.port:' + uuid
        retval = self.vpp.ensure_interface_on_host(if_type, uuid, mac)
        self.vpp.vpp.create_tap.assert_called_once_with('vppfakeuuid',
                                                        mac,
                                                        expected_tag)
        self.vpp.ensure_bridge.assert_called_once_with('br-fakeuuid')
        assert (retval == self.vpp.interfaces[uuid])

    def test_ensure_interface_on_host_vhostuser(self):
        if_type = 'vhostuser'
        uuid = 'fakeuuid'
        mac = 'fakemac'
        expected_tag = 'net-vpp.port:' + uuid
        retval = self.vpp.ensure_interface_on_host(if_type, uuid, mac)
        self.vpp.vpp.create_vhostuser.assert_called_once_with('/tmp/fakeuuid',
                                                              mac,
                                                              expected_tag)
        assert (retval == self.vpp.interfaces[uuid])

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
