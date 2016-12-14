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

from networking_vpp._i18n import _
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
    cfg.StrOpt('etcd_host', default="127.0.0.1",
               help=_("Etcd host IP address(es) to connect etcd client."
                      "It takes two formats: single IP/host or a multiple "
                      "hosts list with this format: 'IP:Port,IP:Port'. "
                      "e.g: 192.168.1.1:2379,192.168.1.2:2379")),
    cfg.IntOpt('etcd_port', default=4001,
               help=_("Etcd port to connect the etcd client. If etcd_host"
                      "is specified as multiple host option, this option"
                      "will be ignored.")),
    cfg.StrOpt('etcd_user', default=None,
               help=_("Username for etcd authentication")),
    cfg.StrOpt('etcd_pass', default=None,
               help=_("Password for etcd authentication")),
    cfg.BoolOpt('enable_vpp_restart', default=False,
                help=_("Agent restarts VPP during startup")),
]

cfg.CONF.register_opts(vpp_opts, "ml2_vpp")
