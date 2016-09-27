#!/usr/bin/python

import etcd
import mock
import socket

from oslo_config import cfg
from oslo_serialization import jsonutils

from neutron.extensions import portbindings
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit.plugins.ml2 import test_plugin
from networking_vpp import mech_vpp


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


class VPPMechanismDriverTestCase(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['vpp']

    @mock.patch('networking_vpp.mech_vpp.etcd.Client.write')
    @mock.patch('networking_vpp.mech_vpp.etcd.Client.read')
    # to suppress thread creation
    @mock.patch('networking_vpp.mech_vpp.eventlet')
    def setUp(self, mock_w, mock_r, mock_event):
        super(VPPMechanismDriverTestCase, self).setUp()
        self.mech = mech_vpp.VPPMechanismDriver()
        self.mech.initialize()

    # given valid  and invalid segments
    valid_segment = {
        api.ID: 'API_ID',
        api.NETWORK_TYPE: constants.TYPE_FLAT,
        api.SEGMENTATION_ID: 'API_SEGMENTATION_ID',
        api.PHYSICAL_NETWORK: 'API_PHYSICAL_NETWORK'}

    invalid_segment = {
        api.ID: 'API_ID',
        api.NETWORK_TYPE: constants.TYPE_NONE,
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
            _new_bound_segment=self.valid_segment)

    def test_get_vif_type(self):
        port_context = self.given_port_context()
        owner = "vhostuser"
        assert (self.mech.get_vif_type(port_context) == owner), \
            "Device owner should have been \'%s\'" % owner
        port_context.current['device_owner'] = "neutron:fake_owner"
        owner = "plugtap"
        assert (self.mech.get_vif_type(port_context) == owner), \
            "Device owner should have been \'%s\'" % owner

    @mock.patch('networking_vpp.mech_vpp.VPPMechanismDriver.physnet_known',
                return_value=True)
    def test_bind_port(self, mock_phys):
        port_context = self.given_port_context()
        vif_details = {
            'vhostuser_socket': "/tmp/%s" % port_context.current['id'],
            'vhostuser_mode': 'client'
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
        assert(self.mech.check_segment(segment, host) is True), \
            "Return value should have been True"
        # then test invalid bind
        segment = port_context.segments_to_bind[1]
        assert(self.mech.check_segment(segment, host) is False), \
            "Return value should have been False"

    def test_phsynet_known(self):
        """ This test is trivial- we're going to fake the input which is
        exactly the output"""
        port_context = self.given_port_context()
        # fake network existence
        segment = port_context.segments_to_bind[0]
        physnet = segment[api.PHYSICAL_NETWORK]
        host = port_context.host
        self.mech.communicator.physical_networks.add((host, physnet))
        assert(self.mech.physnet_known(host, physnet) is True), \
            "Return value for host [%s] and net [%s] should have been True" % (
                host, physnet)
        self.mech.communicator.physical_networks.discard((host, physnet))

    def test_check_vlan_transparency(self):
        # shrircha: this is useless, as the function simply returns false.
        # placeholder, for when this is implemented in the future.
        # this test will need to be updated to reflect this.
        port_context = self.given_port_context()
        assert(self.mech.check_vlan_transparency(port_context) is False), \
            "Return value for port [%s] should have been False" % (
                port_context.current.id)
