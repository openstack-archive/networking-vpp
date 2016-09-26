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

from neutron._i18n import _
from oslo_config import cfg

vpp_opts = [
    cfg.StrOpt('physnets',
               help=_("Comma-separated list of net-name:interface-name for "
                      "physical connections")),
    cfg.StrOpt('vxlan_src_addr',
               help=_("Source address used for VXLAN tunnel packets.")),
    cfg.StrOpt('vxlan_bcast_addr',
               help=_("Broadcast address used to set up VXLAN tunnels.")),
    cfg.StrOpt('vxlan_vrf',
               help=_("VPP's VRF for the encapped VXLAN packets.")),
    cfg.StrOpt('qemu_user',
               help=_("QEMU user. Leave blank for default user")),
    cfg.StrOpt('qemu_group',
               help=_("QEMU group. Leave blank for default group.")),
    cfg.StrOpt('etcd_host', default="127.0.0.1",
               help=_("Etcd host IP address to connect etcd client.")),
    cfg.IntOpt('etcd_port', default=4001,
               help=_("Etcd port to connect the etcd client.")),
]

cfg.CONF.register_opts(vpp_opts, "ml2_vpp")
