#  Copyright (c) 2017 Cisco Systems, Inc.
#  All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
#

from ipaddress import ip_network

from oslo_config import cfg
from oslo_log import log as logging

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron_lib.api.definitions import provider_net as provider
from neutron_lib import constants

from networking_vpp.db import db
from networking_vpp.mech_vpp import EtcdAgentCommunicator

LOG = logging.getLogger(__name__)

LEADIN = '/networking-vpp'

def log_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            LOG.exception('caught exception in callback')
            raise

    return wrapper

class VppL3RouterPlugin(
    common_db_mixin.CommonDbMixin,
    extraroute_db.ExtraRoute_db_mixin,
    l3_gwmode_db.L3_NAT_dbonly_mixin):

    """Implementation of the VPP L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    """
    supported_extension_aliases = ["router", "ext-gw-mode"]

    def get_plugin_type(self):
        return constants.L3

    def get_plugin_description(self):
        """Returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding "
                "using VPP.")

    after_map  = {
        events.PRECOMMIT_CREATE: events.AFTER_CREATE,
        events.PRECOMMIT_UPDATE: events.AFTER_UPDATE,
        events.PRECOMMIT_DELETE: events.AFTER_DELETE}

    def add_track(self, res, ev, change_func):
        """Deal with outputting the results of changes to etcd"""
        registry.subscribe(change_func,
                           res, ev)
        registry.subscribe(self._change_committed,
                           res, self.after_map[ev])

    def _change_committed(self, resource, event, trigger, **kwargs):
        """Prompt etcd forwarding

        We have committed change requests to etcd in the journal.
        Forward them.
        """
        self.communicator.kick()

    def __init__(self):
        super(VppL3RouterPlugin, self).__init__()
        # TODO(ijw): hm, this is a fishy thing to include.  We're only
        # using kick().
        self.communicator = EtcdAgentCommunicator(None)
        self.l3_host = cfg.CONF.ml2_vpp.l3_host

        # Trap all the 
        for ev in (
                events.PRECOMMIT_CREATE,
                events.PRECOMMIT_UPDATE,
                events.PRECOMMIT_DELETE,
        ):
            for res in (resources.ROUTER,
                        resources.ROUTER_INTERFACE,
                        resources.ROUTER_GATEWAY):  # change == update route

                self.add_track(res, ev, 
                               self._router_changing_op)

            for res in (resources.SUBNET_GATEWAY,  # change == readdress interface
                        resources.SUBNET):         # change == readdress interface

                self.add_track(res, ev, 
                               self._subnet_op)

    @log_exceptions
    def _router_changing_op(self, resource, event, trigger, **kwargs):
	"""Manage etcd effects of router-changing operations

        When this happens, we should be determining if this changes the
        behaviour of the network fabric (i.e. changes VPP config) and,
        if it does, updating the details of the router in etcd via the
        journal calls.

        It is important that the journal write is done inside the same
        DB transaction as the commit to the Neutron tables (hence this
        is called inside PRECOMMIT hooks) because if the Neutron commit
        rolls back we absolutely don't want to be updating etcd.
        """

        context = kwargs['context']

        # Minor role is to maintain router VRF allocations.
        # TODO(ijw): this will be done on the agent side with tags in
        # the future.
        if resource == resources.ROUTER:
            if event == events.PRECOMMIT_CREATE:
                db.add_router_vrf(context.session, kwargs['router_id'])
            elif event == events.PRECOMMIT_DELETE:
                db.delete_router_vrf(context.session, kwargs['router_id'])

        # Main role is to spot the router that's been updated.  We
        # don't need the details of the change, we just spew the whole
        # router's information out to etcd on one of these changes.
        if resource == resources.ROUTER:
            router_id = kwargs['router_id']

        elif resource == resources.ROUTER_GATEWAY:
            router_id = kwargs['router_id']
        elif resource == resources.ROUTER_INTERFACE:
            router_id = kwargs['router_id']

        self._router_emit(context, router_id)

    def _subnet_op(self,resource, event, trigger, **kwargs):
        context = kwargs['context']

    def _get_router_intf_details(self, port):
        # Returns a router interface dictionary (suitable for etcd)
        # populated with network and subnet information for the
        # associated subnet, pulled from the port and extra bits
        # structure

        # Get segmentation details for this subnet's network
        intf_dict = {
            'segmentation_id': network[provider.SEGMENTATION_ID],
            'net_type': network[provider.NETWORK_TYPE],
            'physnet': network[provider.PHYSICAL_NETWORK],

            'mtu': port['mtu'],
            'mac': port['mac'],

            'port_id': port['id'],
        }

        ips = []
        for fixed_ip in port['fixed_ips']:
            data = {
                'ip': fixed_ip['address'],
                'prefixlen': fixed_ip['prefixlen'],
            }
            for subnet in port['subnets']:
                if fixed_ip['subnet_id'] == subnet['id']:
                    data.update({
                        'is_ipv6': subnet['address_scope_id'] == constants.IP_VERSION_6,
                        'gateway_ip': subnet['gateway_ip'],
                        'ipv6_ra_mode': subnet['ipv6_ra_mode']
                    })
                    break
            ips.append(data)

        intf_dict['addresses'] = ips
            
        return intf_dict

    def _get_router_details(self, context, router_id):

        routers = self.get_sync_data(context, router_id, active=True)
        # Returns a list of one...
        router = routers[0]

        interfaces = router.get(constants.INTERFACE_KEY, [])

        # Get VRF corresponding to the router
        vrf_id = db.get_router_vrf(context.session, router_id)

        if vrf_id is None:
            # The router has been deleted
            return None


        router_dict = {
            'vrf_id': vrf_id,
        }

        gw_port = router.get('gw_port')
        if gw_port is not None:
            router_dict['gw_port'] = gw_port['id']

        interfaces_dicts = {}
        for f in interfaces:
            interfaces_dicts[interface['id']] = \
                self._get_router_intf_details(f)

        router_dict['interfaces'] = interfaces

        return router_dict

    def _write_router_journal_row(self, context, router_id, router_dict):
        etcd_dir = LEADIN + '/nodes/' + self.l3_host + '/routers/' + router_id
        db.journal_write(context.session, etcd_dir, router_dict)


    def _router_emit(self, context, router_id):
        # We're about to read the DB so we need it to be current, now.
        LOG.error(context.session.new)
        context.session.flush()
        router_data = self._get_router_details(context, router_id)
        db._write_router_journal_row(context, router_id, router_dict)
