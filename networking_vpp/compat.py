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
    # Ocata+
    import neutron_lib.api.definitions.portbindings
    portbindings = neutron_lib.api.definitions.portbindings

except ImportError:
    import neutron.extensions.portbindings
    portbindings = neutron.extensions.portbindings

try:
    # Newton+
    import neutron_lib.context
    context = neutron_lib.context
except ImportError:
    import neutron.context
    context = neutron.context

try:
    # Mitaka+
    import neutron_lib.constants
    import neutron_lib.exceptions

    n_const = neutron_lib.constants
    n_exec = neutron_lib.exceptions

except ImportError:
    import neutron.common.constants
    import neutron.common.exceptions

    n_const = neutron.common.constants
    n_exec = neutron.common.exceptions

try:
    n_const.UUID_PATTERN
except AttributeError:
    HEX_ELEM = '[0-9A-Fa-f]'
    n_const.UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                                     HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                                     HEX_ELEM + '{12}'])

try:
    # Newton+
    import neutron_lib.db.model_base
    import neutron_lib.plugins.directory

    model_base = neutron_lib.db.model_base
    directory = neutron_lib.plugins.directory

except ImportError:
    import neutron.db.model_base
    import neutron.manager

    directory = neutron.manager.NeutronManager
    model_base = neutron.db.model_base

import os
import re

from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib


def monkey_patch():
    """Add backward compatibility to networking-vpp for Liberty.

    This monkey-patches a couple of bits of Neutron
    to enable compatibility with Liberty.
    """
    if 'owns_interface' not in dir(bridge_lib.BridgeDevice):

        def owns_interface(self, interface):
            bridge_interface_fs = \
                "/sys/class/net/%(bridge)s/brif/%(interface)s"
            return os.path.exists(
                bridge_interface_fs % {'bridge': self.name,
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

    if 'disable_ipv6' not in dir(bridge_lib.BridgeDevice):

        def disable_ipv6(self):
            sysctl_name = re.sub(r'\.', '/', self.name)
            cmd = 'net.ipv6.conf.%s.disable_ipv6=1' % sysctl_name
            wrapper = ip_lib.IPWrapper(namespace=self.namespace)
            try:
                wrapper.netns.execute(
                    ['sysctl', '-w', cmd],
                    run_as_root=True,
                    log_fail_as_error=self.log_fail_as_error)
            except RuntimeError:
                return 1
            return 0

        bridge_lib.BridgeDevice.disable_ipv6 = disable_ipv6
