# Copyright (c) 2017 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""VPP Taas service plugin."""
import eventlet
from networking_vpp.compat import context as n_context
from networking_vpp.compat import n_exc
from networking_vpp.constants import LEADIN
from networking_vpp.db import db
from networking_vpp import etcdutils
from networking_vpp.extension import MechDriverExtensionBase

from neutron_lib import constants
from neutron_lib.db import api as lib_db_api
from neutron_taas.extensions import taas as taas_ex
from neutron_taas.services.taas import service_drivers

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
import re


LOG = logging.getLogger(__name__)


class EtcdJournalHelper(object):
    __instance = None

    def __new__(cls, communicator, session):
        if EtcdJournalHelper.__instance is None:
            EtcdJournalHelper.__instance = object.__new__(cls)
            EtcdJournalHelper.__instance._communicator = communicator
            EtcdJournalHelper.__instance._session = session
        return EtcdJournalHelper.__instance

    @classmethod
    def etcd_write(cls, key, value):
        if cls.__instance is not None:
            db.journal_write(cls.__instance._session,
                             key,
                             value)
            cls.__instance._communicator.kick()


class FeatureTaasService(etcdutils.EtcdChangeWatcher):
    """Server side of the TaaS Service functionnality.

    The following etcd key structure is created by this class:
    path : LEADIN/nodes/<hostname>/taas_service/<taas_service_id>
    {"tap_service":
         {"status": "PENDING_CREATE|ACTIVE",
          "description": "",
          "tenant_id": "",
          "project_id": "",
          "port_id": "",
          "id": "",
          "name": ""},
      "taas_id": ,
      "port":
          {"allowed_address_pairs": [],
           "extra_dhcp_opts": [],
           "updated_at": "",
           "device_owner": "",
           "revision_number": ,
           "port_security_enabled": false,
           "binding:profile": {},
           "fixed_ips": [{"subnet_id": "", "ip_address": ""}],
           "id": "",
           "security_groups": [],
           "binding:vif_details":
               {"vhostuser_socket": "",
                "vhostuser_mode": ""},
           "binding:vif_type": "",
           "mac_address": "",
           "project_id": "",
           "status": "",
           "binding:host_id": "",
           "description": "",
           "device_id": "",
           "name": "",
           "admin_state_up": ,
           "network_id": "",
           "tenant_id": "",
           "created_at": "",
           "binding:vnic_type": ""}}

    The following etcd key structure is read by this class:
    path : LEADIN/state_taas/<hostname>/taas_service/<taas_service_id>
    {"port":
        {"iface_idx": ,
         "bridge_domain_id": },
     "ts":
        {"taas_id": ,
         "tap_service":
              {"status": "",
               "description": "",
               "tenant_id": "",
               "project_id": "",
               "port_id": "",
               "id": "",
               "name": ""},
         "port":
          {"allowed_address_pairs": [],
           "extra_dhcp_opts": [],
           "updated_at": "",
           "device_owner": "",
           "revision_number": ,
           "port_security_enabled": false,
           "binding:profile": {},
           "fixed_ips": [{"subnet_id": "", "ip_address": ""}],
           "id": "",
           "security_groups": [],
           "binding:vif_details":
               {"vhostuser_socket": "",
                "vhostuser_mode": ""},
           "binding:vif_type": "",
           "mac_address": "",
           "project_id": "",
           "status": "",
           "binding:host_id": "",
           "description": "",
           "device_id": "",
           "name": "",
           "admin_state_up": ,
           "network_id": "",
           "tenant_id": "",
           "created_at": "",
           "binding:vnic_type": ""}}
     "service_bridge":
         {"segmentation_id": ,
          "if_physnet": "",
           "bridge_domain_id": ,
           "if_uplink_idx": ,
           "network_type": "",
           "physnet": ""}}
    """

    path = 'taas_service'
    nodes_key_space = LEADIN + '/nodes'

    def __init__(self, service_plugin, etcd_client, name, watch_path):
        # The service_plugin is an instance of
        #            neutron_taas.services.taas.taas_plugin.TaasPlugin
        self.service_plugin = service_plugin
        super(FeatureTaasService, self).__init__(etcd_client, name, watch_path)

    def _build_etcd_nodes_path(self, host, uuid):
        return (self.nodes_key_space +
                '/' + host + '/' + self.path + '/' + str(uuid))

    def added(self, key, value):
        """Called when the etcd tap service state key has been created."""
        LOG.info('FeatureTaasService set %s %s', key, str(value))

        if value is None:
            return
        m = re.match('^([^/]+)/taas_service/([^/]+)$', key)
        if m:
            data = jsonutils.loads(value)
            data['ts']['tap_service']['status'] = constants.ACTIVE
            context = n_context.get_admin_context()
            tid = m.group(2)
            self.service_plugin.update_tap_service(context, tid, data['ts'])

    def removed(self, key):
        """Called when the etcd tap service key state has been deleted."""
        LOG.info('FeatureTaasService delete %s' % str(key))

    def create(self, port, taas_data):
        """Server to compute node - creation request.

           Create a key in etcd nodes/<computeNode>/taas_service to request
           the compute node to create a tap service
        """
        host = port['binding:host_id']
        service_id = taas_data['tap_service']['id']
        EtcdJournalHelper.etcd_write(
            self._build_etcd_nodes_path(host, service_id), taas_data)

    def delete(self, host, taas_data):
        """Server to compute node - deletion request.

           Delete the etcd key nodes/<computeNode>/taas_service to request
           the compute node to delete the tap service
        """
        service_id = taas_data['tap_service']['id']
        EtcdJournalHelper.etcd_write(
            self._build_etcd_nodes_path(host, service_id), None)


class FeatureTaasFlow(etcdutils.EtcdChangeWatcher):
    """FeatureTaasFlow.

    Server side of the TaaS Flow functionnality.
    The following etcd key structure is created by this class:
    path : LEADIN/nodes/<hostname>/taas_flow/<taas_flow_id>
    {"tap_flow":
         {"status": "PENDING_CREATE|ACTIVE",
          "direction": "IN|OUT|BOTH",
          "description": "",
          "tenant_id": "",
          "project_id": "",
          "tap_service_id": "",
          "source_port": "",
          "id": "",
          "name": ""},
      "taas_id": ,
      "port_mac": ,
      "tf_host": ,
      "ts_host": ,
      "ts_port_mac": ,
      "port":
          {"allowed_address_pairs": [],
           "extra_dhcp_opts": [],
           "updated_at": "",
           "device_owner": "",
           "revision_number": ,
           "port_security_enabled": false,
           "binding:profile": {},
           "fixed_ips": [{"subnet_id": "", "ip_address": ""}],
           "id": "",
           "security_groups": [],
           "binding:vif_details":
               {"vhostuser_socket": "",
                "vhostuser_mode": ""},
           "binding:vif_type": "",
           "mac_address": "",
           "project_id": "",
           "status": "",
           "binding:host_id": "",
           "description": "",
           "device_id": "",
           "name": "",
           "admin_state_up": ,
           "network_id": "",
           "tenant_id": "",
           "created_at": "",
           "binding:vnic_type": ""}}

    The following etcd key structure is read by this class:
    path : LEADIN/state_taas/<hostname>/taas_service/<taas_service_id>
    {"port":
        {"iface_idx": ,
         "bridge_domain_id": },
     "tf":
        {
        "tap_flow":
             {"status": "PENDING_CREATE|ACTIVE",
              "direction": "IN|OUT|BOTH",
              "description": "",
              "tenant_id": "",
              "project_id": "",
              "tap_service_id": "",
              "source_port": "",
              "id": "",
              "name": ""},
          "taas_id": ,
          "port_mac": ,
          "port":
              {"allowed_address_pairs": [],
               "extra_dhcp_opts": [],
               "updated_at": "",
               "device_owner": "",
               "revision_number": ,
               "port_security_enabled": false,
               "binding:profile": {},
               "fixed_ips": [{"subnet_id": "", "ip_address": ""}],
               "id": "",
               "security_groups": [],
               "binding:vif_details":
                   {"vhostuser_socket": "",
                    "vhostuser_mode": ""},
               "binding:vif_type": "",
               "mac_address": "",
               "project_id": "",
               "status": "",
               "binding:host_id": "",
               "description": "",
               "device_id": "",
               "name": "",
               "admin_state_up": ,
               "network_id": "",
               "tenant_id": "",
               "created_at": "",
               "binding:vnic_type": ""}
            }
     dst_idx:,
     port_idx:,
     remote_span:"true|false",
     "service_bridge":
         {"segmentation_id": ,
          "if_physnet": "",
           "bridge_domain_id": ,
           "if_uplink_idx": ,
           "network_type": "",
           "physnet": ""}
    }
    """

    path = 'taas_flow'
    nodes_key_space = LEADIN + '/nodes'

    def __init__(self, service_plugin, etcd_client, name, watch_path):
        # The service_plugin is an instance of
        #            neutron_taas.services.taas.taas_plugin.TaasPlugin
        self.service_plugin = service_plugin
        super(FeatureTaasFlow, self).__init__(etcd_client, name, watch_path)

    def _build_etcd_nodes_path(self, host, uuid):
        return (self.nodes_key_space +
                '/' + host + '/' + self.path + '/' + str(uuid))

    def added(self, key, value):
        """Called when the etcd tap flow state key has been created."""
        LOG.info('FeatureTaasFlow set %s %s', str(key), str(value))
        if value is None:
            return
        m = re.match('^([^/]+)/taas_flow/([^/]+)$', key)
        if m:
            data = jsonutils.loads(value)
            data['tf']['tap_flow']['status'] = constants.ACTIVE
            context = n_context.get_admin_context()
            tid = m.group(2)
            self.service_plugin.update_tap_flow(context, tid, data['tf'])

    def removed(self, key):
        """Called when the etcd tap flow state key has been deleted."""
        LOG.info('FeatureTaasFlow delete %s' % str(key))

    def create(self, port, data):
        """Server to compute node - creation request."""
        host = port['binding:host_id']
        flow_id = data['tap_flow']['id']
        EtcdJournalHelper.etcd_write(
            self._build_etcd_nodes_path(host, flow_id), data)

    def delete(self, host, flow_id):
        """Server to compute node - deletion request."""
        EtcdJournalHelper.etcd_write(
            self._build_etcd_nodes_path(host, flow_id), None)


class TaasEtcdDriver(service_drivers.TaasBaseDriver):
    """Taas Etcd Service Driver class.

       It uses etcd to communicate with the Taas agents in the
       compute nodes.
    """

    def __init__(self, service_plugin):
        LOG.debug("Loading TaasEtcdDriver.")
        super(TaasEtcdDriver, self).__init__(service_plugin)

        self.client_factory = etcdutils.EtcdClientFactory(cfg.CONF.ml2_vpp)
        etcd_client = self.client_factory.client()
        etcd_helper = etcdutils.EtcdHelper(etcd_client)
        etcd_helper.ensure_dir(LEADIN + '/state_taas')

        self.taas_service = FeatureTaasService(service_plugin,
                                               self.client_factory.client(),
                                               'TaasService',
                                               LEADIN + '/state_taas')
        self.taas_flow = FeatureTaasFlow(service_plugin,
                                         self.client_factory.client(),
                                         'TaasFlow',
                                         LEADIN + '/state_taas')

        eventlet.spawn(self.taas_service.watch_forever)
        eventlet.spawn(self.taas_flow.watch_forever)

    def _get_taas_id(self, context, tf):
        ts = self.service_plugin.get_tap_service(context,
                                                 tf['tap_service_id'])
        # taas_id = (self.service_plugin.get_tap_id_association(
        #    context,
        #    tap_service_id=ts['id'])['taas_id'] +
        #    cfg.CONF.taas.vlan_range_start)
        taas_id = self.service_plugin.get_tap_id_association(
            context,
            tap_service_id=ts['id'])['taas_id']
        return taas_id

    def create_tap_service_precommit(self, context):
        """Send tap service creation message to agent.

        This message includes taas_id that is added vlan_range_start to
        so that the vpp taas agent can use taas_id as VLANID.
        """

        # by default, the status is ACTIVE: wait for creation...
        context.tap_service['status'] = constants.PENDING_CREATE
        ts = context.tap_service
        # Get taas id associated with the Tap Service
        tap_id_association = context._plugin.create_tap_id_association(
            context._plugin_context, ts['id'])
        context.tap_id_association = tap_id_association
        self.service_plugin.update_tap_service(context._plugin_context,
                                               ts['id'],
                                               {'tap_service':
                                                   context.tap_service})
        ts = context.tap_service
        tap_id_association = context.tap_id_association
        # taas_vlan_id = (tap_id_association['taas_id'] +
        #                cfg.CONF.taas.vlan_range_start)
        taas_vlan_id = tap_id_association['taas_id']
        port = self.service_plugin._get_port_details(context._plugin_context,
                                                     ts['port_id'])

        if taas_vlan_id > cfg.CONF.taas.vlan_range_end:
            raise taas_ex.TapServiceLimitReached()

        msg = {"tap_service": ts,
               "taas_id": taas_vlan_id,
               "port": port}

        self.taas_service.create(port, msg)
        return

    def create_tap_service_postcommit(self, context):
        """Send tap service creation message to agent."""
        pass

    def delete_tap_service_precommit(self, context):
        """Send tap service deletion message to agent.

        This message includes taas_id that is added vlan_range_start to
        so that the vpp taas agent can use taas_id as VLANID.
        """
        ts = context.tap_service
        tap_id_association = context.tap_id_association
        # taas_vlan_id = (tap_id_association['taas_id'] +
        #                cfg.CONF.taas.vlan_range_start)
        taas_vlan_id = tap_id_association['taas_id']
        try:
            port = self.service_plugin._get_port_details(
                context._plugin_context,
                ts['port_id'])
            host = port['binding:host_id']
        except n_exc.PortNotFound:
            # if not found, we just pass to None
            port = None
            host = None

        msg = {"tap_service": ts,
               "taas_id": taas_vlan_id,
               "port": port}

        self.taas_service.delete(host, msg)
        return

    def delete_tap_service_postcommit(self, context):
        """Send tap service deletion message to agent."""
        pass

    def create_tap_flow_precommit(self, context):
        """Send tap flow creation message to agent."""
        tf = context.tap_flow
        tf['status'] = constants.PENDING_CREATE
        taas_id = self._get_taas_id(context._plugin_context, tf)

        self.service_plugin.update_tap_flow(context._plugin_context,
                                            tf['id'], {'tap_flow': tf})
        # Extract the host where the source port is located
        port = self.service_plugin._get_port_details(context._plugin_context,
                                                     tf['source_port'])
        tf_host = port['binding:host_id']
        port_mac = port['mac_address']

        # Find the host of the tap service
        ts = self.service_plugin.get_tap_service(context._plugin_context,
                                                 tf['tap_service_id'])
        ts_port = self.service_plugin._get_port_details(
            context._plugin_context,
            ts['port_id'])
        ts_host = ts_port['binding:host_id']
        ts_port_mac = ts_port['mac_address']

        # This status will be set in the callback
        msg = {"tap_flow": tf,
               "port_mac": port_mac,
               "taas_id": taas_id,
               "port": port,
               "ts_port_mac": ts_port_mac,
               "tf_host": tf_host,
               "ts_host": ts_host}
        self.taas_flow.create(port, msg)
        if ts_host != tf_host:
            self.taas_flow.create(ts_port, msg)
        return

    def create_tap_flow_postcommit(self, context):
        """Send tap flow creation message to agent."""
        pass

    def delete_tap_flow_precommit(self, context):
        """Send tap flow deletion message to agent."""
        tf = context.tap_flow
        # Extract the host where the source port is located
        port = self.service_plugin._get_port_details(context._plugin_context,
                                                     tf['source_port'])
        host = port['binding:host_id']

        # Find the host of the tap service
        ts = self.service_plugin.get_tap_service(context._plugin_context,
                                                 tf['tap_service_id'])
        ts_port = self.service_plugin._get_port_details(
            context._plugin_context,
            ts['port_id'])
        ts_host = ts_port['binding:host_id']

        self.taas_flow.delete(host, tf['id'])
        if ts_host != host:
            self.taas_flow.delete(ts_host, tf['id'])
        return

    def delete_tap_flow_postcommit(self, context):
        """Send tap flow deletion message to agent."""
        pass


class TaasVPPDriverExtension(MechDriverExtensionBase):
    def initialize(self, manager):
        pass

    def run(self, communicator):
        self.etcdJournalHelper = \
            EtcdJournalHelper(
                communicator,
                lib_db_api.get_writer_session())
