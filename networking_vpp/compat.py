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

# Some constants and verifier functions have been deprecated but are still
# used by earlier releases of neutron. In order to maintain
# backwards-compatibility with stable/mitaka this will act as a translator
# that passes constants and functions according to version number.


try:
    import neutron_lib.constants
    import neutron_lib.db.model_base
    import neutron_lib.exceptions
    import neutron_lib.plugins.directory

    n_const = neutron_lib.constants
    n_exec = neutron_lib.exceptions
    model_base = neutron_lib.db.model_base
    directory = neutron_lib.plugins.directory

except ImportError:
    import neutron.common.exceptions
    import neutron.constants
    import neutron.db
    import neutron.manager

    n_const = neutron.constants
    n_exec = neutron.common.exceptions
    model_base = neutron.db.model_base
    directory = neutron.manager.NeutronManager

import os

from neutron.agent.linux import bridge_lib


def monkey_patch():
    """Add backward compatibility to networking-vpp for Liberty

    This monkey-patches a couple of bits of Neutron
    to enable compatibility with Liberty.
    """

    if 'owns_interface' not in dir(bridge_lib.BridgeDevice):
        BRIDGE_INTERFACE_FS = "/sys/class/net/%(bridge)s/brif/%(interface)s"

        def owns_interface(self, interface):
            return os.path.exists(
                BRIDGE_INTERFACE_FS % {'bridge': self.name,
                                       'interface': interface})

        bridge_lib.BridgeDevice.owns_interface = owns_interface

    if 'get_log_fail_as_error' not in dir(bridge_lib.BridgeDevice):

        def get_log_fail_as_error(self):
            return self.log_fail_as_error

        bridge_lib.BridgeDevice.get_log_fail_as_error = get_log_fail_as_error

    if 'exists' not in dir(bridge_lib.BridgeDevice):

        def exists(self):
            orig_log_fail_as_error = self.get_log_fail_as_error()
            self.set_log_fail_as_error(False)
            try:
                return bool(self.link.address)
            except RuntimeError:
                return False
            finally:
                self.set_log_fail_as_error(orig_log_fail_as_error)

        bridge_lib.BridgeDevice.exists = exists
