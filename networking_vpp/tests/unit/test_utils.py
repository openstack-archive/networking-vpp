# Copyright (c) 2016 Cisco Systems, Inc.
# All Rights Reserved
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

from networking_vpp.agent import exceptions as vpp_agent_exec
from networking_vpp.agent import utils
from neutron.tests import base
from testtools import ExpectedException
from testtools import matchers


OVERRIDE_PORT = 9999


class FakeConfig(object):
    def __init__(self, host, port, user, pw):
        self.etcd_host = host
        self.etcd_port = port
        self.etcd_user = user
        self.etcd_pass = pw


class TestAgentUtils(base.BaseTestCase):

    def parse_config_test_run(self, host, port, user=None, pw=None):
            fk = FakeConfig(host, port, user, pw)

            cf = utils.EtcdClientFactory(fk)

            return cf.hostconf

    def test_pass_user_password(self):
        # The defaults
        fk = FakeConfig('host', 1, None, None)
        cf = utils.EtcdClientFactory(fk)
        self.assertThat(cf.etcd_user, matchers.Equals(None))
        self.assertThat(cf.etcd_pass, matchers.Equals(None))

        # When set
        fk = FakeConfig('host', 1, 'uuu', 'ppp')
        cf = utils.EtcdClientFactory(fk)
        self.assertThat(cf.etcd_user, matchers.Equals('uuu'))
        self.assertThat(cf.etcd_pass, matchers.Equals('ppp'))

    def test_parse_empty_host_config(self):
        """Test parse_host_config with empty value """
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('', OVERRIDE_PORT)

    def test_parse_fishy_host_config(self):
        """Test parse_host_config with non-string value """
        with ExpectedException(vpp_agent_exec.InvalidEtcHostsConfig):
            self.parse_config_test_run(1, OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostsConfig):
            self.parse_config_test_run(None, OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run(',', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1,', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run(',host2', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1,,host2', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1:', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1::123', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1:123:123', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1:123:', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1:,host2', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1::123,host2', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1:123:123,host2', OVERRIDE_PORT)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run('host1:123:,host2', OVERRIDE_PORT)

    def test_parse_single_host_config(self):
        """Test parse_host_config with an IP or Host value """
        ret = self.parse_config_test_run('192.168.1.10', OVERRIDE_PORT)
        self.assertThat(ret, matchers.Equals((('192.168.1.10',
                                               OVERRIDE_PORT),)))

        ret = self.parse_config_test_run('host1.lab1.mc', OVERRIDE_PORT)
        self.assertThat(ret, matchers.Equals((('host1.lab1.mc',
                                               OVERRIDE_PORT,),)))

        ret = self.parse_config_test_run('192.168.1.10:123', OVERRIDE_PORT)
        self.assertThat(ret, matchers.Equals((('192.168.1.10', 123,),)))

        ret = self.parse_config_test_run('host1.lab1.mc:123', OVERRIDE_PORT)
        self.assertThat(ret, matchers.Equals((('host1.lab1.mc', 123,),)))

    def test_parse_multi_host_config(self):
        """Test parse_host_config with multiple host-port values """
        hosts = '192.168.1.10:1234,192.168.1.11:1235,192.168.1.12:1236'
        ret = self.parse_config_test_run(hosts, OVERRIDE_PORT)
        self.assertTrue(isinstance(ret, tuple))
        self.assertThat(ret, matchers.Equals(
            (('192.168.1.10', 1234),
             ('192.168.1.11', 1235),
             ('192.168.1.12', 1236))
        ))

        hosts = '192.168.1.10:1234,192.168.1.11,192.168.1.12:1236'
        ret = self.parse_config_test_run(hosts, OVERRIDE_PORT)
        self.assertTrue(isinstance(ret, tuple))
        self.assertThat(ret, matchers.Equals(
            (('192.168.1.10', 1234),
             ('192.168.1.11', OVERRIDE_PORT),
             ('192.168.1.12', 1236))
        ))

    def test_parse_single_host_invalid_config(self):
        """Test parse_host_config with invalid host-port value """
        hosts = '192.168.1.10:fred,192.168.1.11,192.168.1.12:1236'
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run(hosts, OVERRIDE_PORT)

    def test_parse_multi_host_invalid_config(self):
        """Test parse_host_config with invalid host-port value """
        hosts = '192.168.1.10:fred,192.168.1.11,192.168.1.12:1236'
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            self.parse_config_test_run(hosts, OVERRIDE_PORT)

    def test_parse_single_host_new_format(self):
        """Test parse_host_config with single host new format """
        hosts = '192.168.1.10:1234'
        ret = self.parse_config_test_run(hosts, OVERRIDE_PORT)
        self.assertTrue(isinstance(ret, tuple))
        self.assertThat(ret, matchers.Equals(
            (('192.168.1.10', 1234),)
        ))
