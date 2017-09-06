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
    cfg.StrOpt('gpe_src_cidr', default=None,
               help=_("The source_IP/Mask used for GPE tunnel packets. ")),
    cfg.StrOpt('gpe_locators', default=None,
               help=_("The physnet name(s) used as the underlay "
                      "(i.e. locator) interface by GPE. The agent will "
                      "program the GPE source CIDR on this interface "
                      "and will assume that it has Layer3 reachability "
                      "with all other GPE locator interfaces "
                      "specified on compute and network nodes. In the "
                      "current implementation only a single locator "
                      "is supported.")),
    cfg.StrOpt('etcd_host', default="127.0.0.1",
               help=_("Etcd host IP address(es) to connect etcd client."
                      "It takes two formats: single IP/host or a multiple "
                      "hosts list with this format: 'IP:Port,IP:Port'. "
                      "e.g: 192.168.1.1:2379,192.168.1.2:2379.  If port "
                      "is absent, etcd_port is used.")),
    cfg.IntOpt('etcd_port', default=4001,
               help=_("Etcd port to connect the etcd client.  This can "
                      "be overridden on a per-host basis if the multiple "
                      "host form of etcd_host is used.")),
    cfg.StrOpt('etcd_user', default=None,
               help=_("Username for etcd authentication")),
    cfg.StrOpt('etcd_pass', default=None,
               help=_("Password for etcd authentication")),
    # TODO(ijw): make false default
    cfg.BoolOpt('etcd_insecure_explicit_disable_https', default=True,
                help=_("Use TLS to access etcd")),
    cfg.StrOpt('etcd_ca_cert', default=None,
               help=_("etcd CA certificate file path")),
    cfg.IntOpt('etcd_write_time', default=20,
               help=_("The period of time alloted to etcd write before it is "
                      "timed out.")),
    cfg.IntOpt('forward_worker_master_lease_time', default=30,
               help=_("The slice of time allotted for a journal forward worker"
                      " thread to run once elected.")),
    cfg.IntOpt('forward_worker_recovery_time', default=3,
               help=_("The worst case time a new forward worker master is "
                      "elected after a forward worker's mastership expires. "
                      "etcd updates may stall for a total of "
                      "forward_worker_master_lease_time plus "
                      "forward_worker_recovery_time.")),
    cfg.IntOpt('db_query_time', default=60,
               help=_("The period of a db query can run before it is timed "
                      "out. This is to ensure master election time is extended"
                      " accordingly")),
    cfg.BoolOpt('enable_vpp_restart', default=False,
                help=_("Agent restarts VPP during startup")),
    cfg.StrOpt('vhost_user_dir', default='/tmp',
               help=_("vhostuser socket directory")),
    cfg.IntOpt('mac_age', default=180,
               help=_("bridge domain MAC aging TTL (in seconds)")),
    cfg.IntOpt('vpp_cmd_queue_len', default=None,
               help=_("Size of the VPP command queue (in messages)")),
    cfg.StrOpt('l3_host', default="127.0.0.1",
               help=_("Hostname to render L3 services on.")),
]

cfg.CONF.register_opts(vpp_opts, "ml2_vpp")
