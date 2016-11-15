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

import os

from neutron.agent.linux import bridge_lib


def monkey_patch():
    """Add backward compatibility to networking-vpp for Liberty

    This monkey-patches a couple of bits of Neutron
    to enable compatibility with Liberty.
    """

    # Liberty does not include the 'owns_interface' function
    if 'owns_interface' not in dir(bridge_lib.BridgeDevice):

        BRIDGE_INTERFACE_FS = (bridge_lib.BRIDGE_FS +
                               "%(bridge)s/brif/%(interface)s")

        def owns_interface(self, interface):
            return os.path.exists(
                BRIDGE_INTERFACE_FS % {'bridge': self.name,
                                       'interface': interface})

        bridge_lib.BridgeDevice.owns_interface = owns_interface
