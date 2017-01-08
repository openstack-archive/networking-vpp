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


class TestAgentUtils(base.BaseTestCase):
    def test_parse_empty_host_config(self):
        """Test parse_host_config with empty value """
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('')

    def test_parse_fishy_host_config(self):
        """Test parse_host_config with non-string value """
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config(1)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config(None)
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config(',')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1,')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config(',host2')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1,,host2')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1:')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1::123')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1:123:123')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1:123:')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1:,host2')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1::123,host2')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1:123:123,host2')
        with ExpectedException(vpp_agent_exec.InvalidEtcHostConfig):
            utils.parse_host_config('host1:123:,host2')

    def test_parse_single_host_config(self):
        """Test parse_host_config with an IP or Host value """
        ret = utils.parse_host_config('192.168.1.10')
        self.assertThat(ret, matchers.Equals(('192.168.1.10',)))

        ret = utils.parse_host_config('host1.lab1.mc')
        self.assertThat(ret, matchers.Equals(('host1.lab1.mc',)))

        ret = utils.parse_host_config('192.168.1.10:123')
        self.assertThat(ret, matchers.Equals(('192.168.1.10', 123)))

        ret = utils.parse_host_config('host1.lab1.mc:123')
        self.assertThat(ret, matchers.Equals(('host1.lab1.mc', 123)))

    def test_parse_multi_host_config(self):
        """Test parse_host_config with multiple host-port values """
        hosts = '192.168.1.10:1234,192.168.1.11:1235,192.168.1.12:1236'
        ret = utils.parse_host_config(hosts)
        self.assertTrue(isinstance(ret, tuple))
        self.assertThat(ret, matchers.Equals(
            (('192.168.1.10', 1234),
             ('192.168.1.11', 1235),
             ('192.168.1.12', 1236))
        ))

        hosts = '192.168.1.10:1234,192.168.1.11,192.168.1.12:1236'
        ret = utils.parse_host_config(hosts)
        self.assertTrue(isinstance(ret, tuple))
        self.assertThat(ret, matchers.Equals(
            (('192.168.1.10', 1234),
             '192.168.1.11',
             ('192.168.1.12', 1236))
        ))

    def test_parse_single_host_invalid_config(self):
        """Test parse_host_config with invalid host-port value """
        hosts = '192.168.1.10:fred,192.168.1.11,192.168.1.12:1236'
        with ExpectedException(vpp_agent_exec.InvalidEtcHostsConfig):
            utils.parse_host_config(hosts)

    def test_parse_multi_host_invalid_config(self):
        """Test parse_host_config with invalid host-port value """
        hosts = '192.168.1.10:fred,192.168.1.11,192.168.1.12:1236'
        with ExpectedException(vpp_agent_exec.InvalidEtcHostsConfig):
            utils.parse_host_config(hosts)

    def test_parse_single_host_new_format(self):
        """Test parse_host_config with single host new format """
        hosts = '192.168.1.10:1234,'
        ret = utils.parse_host_config(hosts)
        self.assertTrue(isinstance(ret, tuple))
        self.assertThat(ret, matchers.Equals(
            (('192.168.1.10', 1234),)
        ))

        hosts = '192.168.1.10:1234'
        ret = utils.parse_host_config(hosts)
        self.assertTrue(isinstance(ret, tuple))
        self.assertThat(ret, matchers.Equals(
            (('192.168.1.10', 1234),)
        ))
