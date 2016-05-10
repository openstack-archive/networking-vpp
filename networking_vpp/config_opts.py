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

from oslo_config import cfg

vpp_opts = [
    cfg.StrOpt('agents',
               help=_("HTTP URLs of agents on compute nodes.")),
    cfg.StrOpt('vlan_trunk_if',
               help=_("VPP's interface name for the VLAN trunk")),
    cfg.StrOpt('vxlan_src_addr',
               help=_("Source address used for VXLAN tunnel packets.")),
    cfg.StrOpt('vxlan_bcast_addr',
               help=_("Broadcast address used to set up VXLAN tunnels.")),
    cfg.StrOpt('vxlan_vrf',
               help=_("VPP's VRF for the encapped VXLAN packets.")),
]

cfg.CONF.register_opts(vpp_opts, "ml2_vpp")
