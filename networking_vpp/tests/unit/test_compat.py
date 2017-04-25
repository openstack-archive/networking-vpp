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

from networking_vpp import compat

from neutron.agent.linux import bridge_lib  # flake8: noqa: N530
from neutron.tests import base  # flake8: noqa: N530


class TestMonkeyPatch(base.BaseTestCase):
    def test_bridge_lib_compatibility(self):
        """Test monkey patch applies additional function to the BridgeDevice"""
        compat.monkey_patch()
        self.assertTrue('owns_interface' in dir(bridge_lib.BridgeDevice))
        self.assertTrue('exists' in dir(bridge_lib.BridgeDevice))
        self.assertTrue(
            'get_log_fail_as_error' in dir(bridge_lib.BridgeDevice))
        self.assertTrue(
            'disable_ipv6' in dir(bridge_lib.BridgeDevice))
