# Copyright (c) 2013 OpenStack Foundation
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

from networking_vpp.compat import n_exc
from networking_vpp import config_opts
from networking_vpp import constants as nvpp_const
from networking_vpp.db.models import GpeAllocation as gpe_alloc_obj
from networking_vpp.db.models import GpeEndpoints as gpe_ep_obj
from oslo_config import cfg
from oslo_log import log as logging

from neutron.plugins.ml2.drivers import type_tunnel

LOG = logging.getLogger(__name__)


class GpeTypeDriver(type_tunnel.EndpointTunnelTypeDriver):

    def __init__(self):
        super(GpeTypeDriver, self).__init__(gpe_alloc_obj, gpe_ep_obj)

    def get_type(self):
        return nvpp_const.TYPE_GPE

    def initialize(self):
        try:
            config_opts.register_vpp_opts(cfg.CONF)
            self._initialize(cfg.CONF.ml2_vpp.gpe_vni_ranges)
        except n_exc.NetworkTunnelRangeError:
            LOG.exception("Failed to parse gpe_vni_ranges from config. "
                          "Service terminated!")
            raise SystemExit()

    def get_endpoints(self):
        """Get all gpe endpoints from the database."""
        gpe_endpoints = self._get_endpoints()
        return [{'ip_address': gpe_endpoint.ip_address,
                 'udp_port': gpe_endpoint.udp_port,
                 'host': gpe_endpoint.host}
                for gpe_endpoint in gpe_endpoints]

    def add_endpoint(self, ip, host, udp_port=nvpp_const.GPE_UDP_PORT):
        return self._add_endpoint(ip, host, udp_port=udp_port)

    def get_mtu(self, physical_network=None):
        mtu = super(GpeTypeDriver, self).get_mtu()
        return mtu - nvpp_const.GPE_ENCAP_OVERHEAD if mtu else 0
