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

from networking_vpp._i18n import _


class InvalidEtcdCAConfig(Exception):
    message = _("Invalid etcd CA config.")


class InvalidEtcHostsConfig(Exception):
    message = _("Invalid etc host config. Expect comma-separated list of "
                "<Host> or <Host:Port> format")


class InvalidEtcHostConfig(Exception):
    message = _("Invalid etc host config. Expect an IP or host name in "
                "the form <Host> or <Host:Port>")
