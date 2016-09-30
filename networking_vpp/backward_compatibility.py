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

from distutils.version import StrictVersion
from neutron import version

# Some constants and verifier functions have been deprecated but are still
# used by earlier releases of neutron. In order to maintain
# backwards-compatibility with stable/mitaka this will act as a translator
# that passes constants and functions according to version number.

IS_PRE_NEWTON = True
if StrictVersion(str(version.version_info)) >= StrictVersion('9.0.0'):
    # >= Newton
    IS_PRE_NEWTON = False
elif StrictVersion(str(version.version_info)) >= StrictVersion('8.0.0'):
    # Mitaka <= version < Newton 
    from neutron_lib import constants as nl_const
    DEVICE_OWNER_PREFIXES = nl_const.DEVICE_OWNER_PREFIXES
else:
    # version < Mitaka
    from neutron.common import constants as n_const
    DEVICE_OWNER_PREFIXES = n_const.DEVICE_OWNER_PREFIXES
