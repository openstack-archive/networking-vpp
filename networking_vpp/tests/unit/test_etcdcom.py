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

from etcd import EtcdResult
from networking_vpp import config_opts
from networking_vpp import mech_vpp
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.tests import base
from oslo_config import cfg


FAKE_PORT = {'status': 'DOWN',
             'binding:host_id': '',
             'allowed_address_pairs': [],
             'device_owner': 'fake_owner',
             'binding:profile': {},
             'fixed_ips': [],
             'id': '1',
             'security_groups': [],
             'allowed_address_pairs': [],
             'fixed_ips': [],
             'device_id': 'fake_device',
             'name': '',
             'admin_state_up': True,
             'network_id': 'c13bba05-eb07-45ba-ace2-765706b2d701',
             'tenant_id': 'bad_tenant_id',
             'binding:vif_details': {},
             'binding:vnic_type': 'normal',
             'binding:vif_type': 'unbound',
             'mac_address': '12:34:56:78:21:b6'}
LEADIN = '/networking-vpp'
valid_segment = {
    api.ID: 'fake_id',
    api.NETWORK_TYPE: constants.TYPE_FLAT,
    api.SEGMENTATION_ID: 'fake_segId',
    api.PHYSICAL_NETWORK: 'fake_physnet',
    api.BOUND_SEGMENT: 'fake_segment',
    api.BOUND_DRIVER: 'vpp'}
invalid_segment = {
    api.ID: 'API_ID',
    api.NETWORK_TYPE: constants.TYPE_NONE,
    api.SEGMENTATION_ID: 'API_SEGMENTATION_ID',
    api.PHYSICAL_NETWORK: 'API_PHYSICAL_NETWORK'}


class EtcdAgentCommunicatorTestCase(base.BaseTestCase):
    _mechanism_drivers = ['vpp']

    @mock.patch('networking_vpp.mech_vpp.etcd.Client')
    # to suppress thread creation
    @mock.patch('networking_vpp.mech_vpp.eventlet')
    @mock.patch('networking_vpp.mech_vpp.etcd.Client.write')
    @mock.patch('networking_vpp.mech_vpp.etcd.Client.read')
    def setUp(self, mock_r, mock_w, mock_event, mock_client):
        super(EtcdAgentCommunicatorTestCase, self).setUp()
        cfg.CONF.register_opts(config_opts.vpp_opts, "ml2_vpp")
        self.etcd_client = mech_vpp.EtcdAgentCommunicator()

    def test_find_physnets(self):
        child = {'key': "/networking-vpp/state/vpp0/physnets/testnet",
                 'value': "1",
                 'expiration': None,
                 'ttl': None,
                 'modifiedIndex': 5,
                 'createdIndex': 1,
                 'newKey': False,
                 'dir': False,
                 }
        parent = {"node": {
            'key': "/networking-vpp",
            'value': None,
            'expiration': None,
            'ttl': None,
            'modifiedIndex': 5,
            'createdIndex': 1,
            'newKey': False,
            'dir': False,
        }}
        result = EtcdResult(**parent)
        result._children = [child]
        self.etcd_client.etcd_client.read.return_value = result
        retval = self.etcd_client.find_physnets()
        assert ('vpp0', 'testnet') in retval, \
            "Return value should have contained ('vpp0', 'testnet')"

    def test_port_path(self):
        """A trivial test"""
        host = 'vpp0'
        port = {'id': '1234-5678-9012-3456'}
        assert (self.etcd_client._port_path(host, port) ==
                "/networking-vpp/nodes/vpp0/ports/1234-5678-9012-3456")

    def test_kick(self):
        self.etcd_client.db_q_ev.ready.return_value = False
        self.etcd_client.kick()
        self.etcd_client.db_q_ev.send.assert_called_once_with(1)

    def given_port_context(self):
        from neutron.plugins.ml2 import driver_context as ctx

        # given NetworkContext
        network = mock.MagicMock(spec=api.NetworkContext)

        # given port context
        return mock.MagicMock(
            spec=ctx.PortContext, current=FAKE_PORT.copy(),
            segments_to_bind=[valid_segment, invalid_segment],
            network=network,
            _plugin_context=mock.MagicMock(),
            binding_levels=[valid_segment],
            original_binding_levels=[valid_segment])

    @mock.patch('networking_vpp.mech_vpp.db')
    def test_bind(self, m_db):
        port_context = self.given_port_context()
        session = port_context._plugin_context.session
        port = port_context.current
        host = port_context.host
        segment = port_context.segments_to_bind[0]
        mac_address = port_context.current['mac_address']
        security_groups = port_context.current['security_groups']
        allowed_address_pairs = port_context.current['allowed_address_pairs']
        fixed_ips = port_context.current['fixed_ips']
        mtu = 1500
        physnet = segment[api.PHYSICAL_NETWORK]
        network_type = segment[api.NETWORK_TYPE]
        segmentation_id = segment.get(api.SEGMENTATION_ID, 0)
        binding_type = 'vhostuser'
        test_data = {
            'mac_address': mac_address,
            'mtu': mtu,
            'physnet': physnet,
            'network_type': network_type,
            'segmentation_id': segmentation_id,
            'binding_type': binding_type,
            'security_groups': security_groups,
            'allowed_address_pairs': allowed_address_pairs,
            'fixed_ips': fixed_ips
        }
        self.etcd_client.bind(
            session,
            port,
            segment,
            host,
            binding_type)
        m_db.journal_write.assert_called_once_with(
            session,
            self.etcd_client._port_path(port_context.host,
                                        port_context.current),
            test_data)

    @mock.patch('networking_vpp.mech_vpp.db')
    def test_unbind(self, m_db):
        port_context = self.given_port_context()
        session = port_context._plugin_context.session
        port = port_context.current
        host = port_context.host
        self.etcd_client.unbind(
            session,
            port,
            host)
        m_db.journal_write.assert_called_once_with(
            session,
            self.etcd_client._port_path(port_context.host,
                                        port_context.current),
            None)

    def test_do_etcd_update_delete(self):
        key = 'test'
        val = None
        self.etcd_client.do_etcd_update(key, val)
        self.etcd_client.etcd_client.delete.assert_called_once_with(key)

    def test_do_etcd_update_write(self):
        key = 'test'
        val = 'hello'
        self.etcd_client.do_etcd_update(key, val)
        self.etcd_client.etcd_client.write.assert_called_with(
            key, '\"' + val + '\"')

    def test_do_etcd_mkdir(self):
        path = "/networking-vpp/"
        self.etcd_client.do_etcd_mkdir(path)
        self.etcd_client.etcd_client.write.assert_called_with(path,
                                                              None, dir=True)
