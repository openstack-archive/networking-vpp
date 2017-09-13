
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

from networking_vpp import compat
from networking_vpp import config_opts

import etcd
from networking_vpp.compat import plugin_constants
from networking_vpp import mech_vpp
try:
    # TODO(ijw): TEMPORARY, better fix coming that reverses this
    from neutron.plugins.ml2 import config
except ImportError:
    from neutron.conf.plugins.ml2 import config
    config.register_ml2_plugin_opts()
from neutron.plugins.ml2 import driver_api as api
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2

from oslo_config import cfg


FAKE_PORT = {'status': 'DOWN',
             'binding:host_id': '',
             'allowed_address_pairs': [],
             'device_owner': 'fake_owner',
             'binding:profile': {},
             'fixed_ips': [],
             'id': '1',
             'security_groups': [],
             'device_id': 'fake_device',
             'name': '',
             'admin_state_up': True,
             'network_id': 'c13bba05-eb07-45ba-ace2-765706b2d701',
             'tenant_id': 'bad_tenant_id',
             'binding:vif_details': {},
             'binding:vnic_type': 'normal',
             'binding:vif_type': 'unbound',
             'mac_address': '12:34:56:78:21:b6'}


class VPPMechanismDriverTestCase(
    test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
    base.BaseTestCase):
    _mechanism_drivers = ['vpp']

    def etcd_client(self):
        # This factory is intended to make many clients, but we return
        # one so we can see how it's used
        return self.client

    # to suppress thread creation
    @mock.patch('networking_vpp.mech_vpp.eventlet')
    @mock.patch('etcd.Client')
    @mock.patch('networking_vpp.etcdutils.EtcdClientFactory.client')
    def setUp(self, mock_eventlet, mock_client, mock_make_client):
        compat.register_ml2_base_opts(cfg.CONF)
        compat.register_securitygroups_opts(cfg.CONF)
        config_opts.register_vpp_opts(cfg.CONF)

        mock_make_client.side_effect = self.etcd_client
        self.client = etcd.Client()

        cfg.CONF.set_override('mechanism_drivers',
                              ['logger', 'vpp'], 'ml2')
        cfg.CONF.set_override('core_plugin',
                              'neutron.plugins.ml2.plugin.Ml2Plugin')
        core_plugin = cfg.CONF.core_plugin
        super(VPPMechanismDriverTestCase, self).setUp(plugin=core_plugin)
        self.mech = mech_vpp.VPPMechanismDriver()
        self.mech.initialize()

    # given valid  and invalid segments
    valid_segment = {
        api.ID: 'fake_id',
        api.NETWORK_TYPE: plugin_constants.TYPE_FLAT,
        api.SEGMENTATION_ID: 'fake_segId',
        api.PHYSICAL_NETWORK: 'fake_physnet',
        api.BOUND_SEGMENT: 'fake_segment',
        api.BOUND_DRIVER: 'vpp'}

    invalid_segment = {
        api.ID: 'API_ID',
        api.NETWORK_TYPE: plugin_constants.TYPE_NONE,
        api.SEGMENTATION_ID: 'API_SEGMENTATION_ID',
        api.PHYSICAL_NETWORK: 'API_PHYSICAL_NETWORK'}

    def given_port_context(self):
        from neutron.plugins.ml2 import driver_context as ctx

        # given NetworkContext
        network = mock.MagicMock(spec=api.NetworkContext)

        # given port context
        return mock.MagicMock(
            spec=ctx.PortContext, current=FAKE_PORT.copy(),
            segments_to_bind=[self.valid_segment, self.invalid_segment],
            network=network,
            _plugin_context=mock.MagicMock(),
            binding_levels=[self.valid_segment],
            original_binding_levels=[self.valid_segment])

    def test_get_vif_type(self):
        port_context = self.given_port_context()
        owner = "vhostuser"
        self.assertEqual(
            self.mech.get_vif_type(port_context), owner,
            "Device owner should have been \'%s\'" % owner)
        port_context.current['device_owner'] = "neutron:fake_owner"
        owner = "tap"
        self.assertEqual(
            self.mech.get_vif_type(port_context), owner,
            "Device owner should have been \'%s\'" % owner)

    @mock.patch('networking_vpp.mech_vpp.VPPMechanismDriver.physnet_known',
                return_value=True)
    def test_bind_port(self, mock_phys):
        port_context = self.given_port_context()
        vif_details = {
            'vhostuser_socket': "/tmp/%s" % port_context.current['id'],
            'vhostuser_mode': 'server'
            }
        self.mech.bind_port(port_context)
        port_context.set_binding.assert_called_once_with(
            self.valid_segment[api.ID], 'vhostuser',
            vif_details)

    @mock.patch('networking_vpp.mech_vpp.VPPMechanismDriver.physnet_known',
                return_value=True)
    def test_bind_port_with_vhost_dir(self, mock_phys):
        """Test bind port with vhost dir option."""
        cfg.CONF.set_override("vhost_user_dir", '/vhostdir1', 'ml2_vpp')
        port_context = self.given_port_context()
        vif_details = {
            'vhostuser_socket': "/vhostdir1/%s" % port_context.current['id'],
            'vhostuser_mode': 'server'
            }
        self.mech.bind_port(port_context)
        port_context.set_binding.assert_called_once_with(
            self.valid_segment[api.ID], 'vhostuser',
            vif_details)

    @mock.patch('networking_vpp.mech_vpp.VPPMechanismDriver.physnet_known',
                return_value=True)
    def test_check_segment(self, mock_phys):
        port_context = self.given_port_context()
        # first test valid
        segment = port_context.segments_to_bind[0]
        host = port_context.host
        self.assertEqual(self.mech.check_segment(segment, host), True)
        # then test invalid bind
        segment = port_context.segments_to_bind[1]
        self.assertEqual(self.mech.check_segment(segment, host), False)

    def test_check_vlan_transparency(self):
        # shrircha: this is useless, as the function simply returns false.
        # placeholder, for when this is implemented in the future.
        # this test will need to be updated to reflect this.
        port_context = self.given_port_context()
        self.assertFalse(self.mech.check_vlan_transparency(port_context))

    @mock.patch('networking_vpp.mech_vpp.EtcdAgentCommunicator.unbind')
    @mock.patch('networking_vpp.mech_vpp.EtcdAgentCommunicator.bind')
    @mock.patch('networking_vpp.mech_vpp.VPPMechanismDriver.'
                '_insert_provisioning_block')
    def test_update_port_precommit(self, m_bind, m_unbind, m_insert_block):
        port_context = self.given_port_context()
        current_bind = port_context.binding_levels[-1]
        self.mech.update_port_precommit(port_context)
        self.mech.communicator.bind.assert_called_once_with(
            port_context._plugin_context.session,
            port_context.current,
            current_bind[api.BOUND_SEGMENT],
            port_context.host,
            'vhostuser')
        self.mech.communicator.unbind.assert_called_once_with(
            port_context._plugin_context.session,
            port_context.original,
            port_context.original_host,
            'fake_segment'
            )
        # reset mocks and set the original host the same with host
        self.mech.communicator.bind.reset_mock()
        self.mech.communicator.unbind.reset_mock()
        port_context.original_host = "hostA"
        port_context.host = "hostA"
        self.mech.update_port_precommit(port_context)
        self.mech.communicator.bind.assert_called_once_with(
            port_context._plugin_context.session,
            port_context.current,
            current_bind[api.BOUND_SEGMENT],
            port_context.host,
            'vhostuser')
        # TODO(ijw): This *ought* to be 'assert_called_once_with' but
        # (per the comment in mech_vpp.py) if we use it in practice
        # with the host change test then we don't call it at all.
        self.mech._insert_provisioning_block.assert_called_with(
            port_context)
        self.mech.communicator.unbind.assert_not_called()

    @mock.patch('networking_vpp.mech_vpp.EtcdAgentCommunicator.kick')
    def test_update_port_postcommit(self, m_kick):
        port_context = self.given_port_context()
        self.mech.update_port_postcommit(port_context)
        self.mech.communicator.kick.assert_called_once()
        port_context.binding_levels = [None]
        self.mech.update_port_postcommit(port_context)
        self.mech.communicator.kick.assert_called()

    @mock.patch('networking_vpp.mech_vpp.EtcdAgentCommunicator.unbind')
    def test_delete_port_precommit(self, m_unbind):
        port_context = self.given_port_context()
        self.mech.delete_port_precommit(port_context)
        self.mech.communicator.unbind.called_once_with(
            port_context._plugin_context.session,
            port_context.current,
            port_context.host)

    @mock.patch('networking_vpp.mech_vpp.EtcdAgentCommunicator.kick')
    def test_delete_port_postcommit(self, m_kick):
        port_context = self.given_port_context()
        self.mech.delete_port_postcommit(port_context)
        self.mech.communicator.kick.assert_called_once()


class EtcdAgentCommunicatorTestCases(base.BaseTestCase):
    def setUp(self):
        compat.register_ml2_base_opts(cfg.CONF)
        compat.register_securitygroups_opts(cfg.CONF)
        config_opts.register_vpp_opts(cfg.CONF)

        super(EtcdAgentCommunicatorTestCases, self).setUp()

    @mock.patch('etcd.Client')
    def test_etcd_no_config(self, mock_client):
        # etcd_port should default to 127.0.0.1
        # etcd_port is left at the default: 4001

        def callback(host, port):
            pass
        mech_vpp.EtcdAgentCommunicator(callback)
        mock_client.assert_called_once_with(
            allow_reconnect=True,
            host=(('127.0.0.1', 4001,),),
            password=None,
            username=None)

    @mock.patch('etcd.Client')
    def test_etcd_single_host_config(self, mock_client):
        cfg.CONF.set_override("etcd_host", '127.0.0.1', 'ml2_vpp')
        # etcd_port is left at the default: 4001

        def callback(host, port):
            pass
        mech_vpp.EtcdAgentCommunicator(callback)
        mock_client.assert_called_once_with(
            allow_reconnect=True,
            host=(('127.0.0.1', 4001,),),
            password=None,
            username=None)

    @mock.patch('etcd.Client')
    def test_etcd_multi_hosts_config_port_override(self, mock_client):
        hosts = '192.168.1.10:1234,192.168.1.11,192.168.1.12:1236'
        cfg.CONF.set_override("etcd_host", hosts, 'ml2_vpp')
        cfg.CONF.set_override("etcd_port", 9889, 'ml2_vpp')

        def callback(host, port):
            pass
        mech_vpp.EtcdAgentCommunicator(callback)
        mock_client.assert_called_once_with(
            allow_reconnect=True,
            host=(('192.168.1.10', 1234,),
                  ('192.168.1.11', 9889,),
                  ('192.168.1.12', 1236,)),
            password=None,
            username=None)
