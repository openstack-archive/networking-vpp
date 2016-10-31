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

from networking_vpp import config_opts
from networking_vpp import mech_vpp
from neutron.tests import base
from oslo_config import cfg


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

    def test_kick(self):
        self.etcd_client.db_q_ev.ready.return_value = False
        self.etcd_client.kick()
        self.etcd_client.db_q_ev.send.assert_called_once_with(1)

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
