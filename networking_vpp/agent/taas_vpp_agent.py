# Copyright (c) 2017 Cisco Systems, Inc.
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

import etcd
from networking_vpp.constants import LEADIN
from networking_vpp import etcdutils
from networking_vpp.extension import VPPAgentExtensionBase
import neutron.agent.linux.ip_lib as ip_lib
from oslo_serialization import jsonutils


class TaasServiceAgentWatcher(etcdutils.EtcdChangeWatcher):
    path = 'taas_service'

    def __init__(self, host, etcd_client_factory, vppf):
        self._node_key_space = LEADIN + '/nodes/%s/%s' % (host, self.path)
        self._state_key_space = LEADIN + \
            '/state_taas/%s/%s' % (host, self.path)
        self.etcd_client = etcd_client_factory.client()
        self.vppf = vppf
        self._host = host
        etcd_helper = etcdutils.EtcdHelper(self.etcd_client)
        etcd_helper.ensure_dir(self._node_key_space)
        etcd_helper.ensure_dir(self._state_key_space)
        super(TaasServiceAgentWatcher, self).__init__(self.etcd_client,
                                                      self.path,
                                                      self._node_key_space)

    def added(self, key, value):
        tap_service_id = key
        data = jsonutils.loads(value)
        port_path = (LEADIN + '/nodes/' + self._host + '/ports/' +
                     str(data['tap_service']['port_id']))
        try:
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            physnet = port_info['physnet']
            network_type = port_info['network_type']

            # Need to put the tapped packets in a dedicated VLAN
            network_type = 'vlan'

            port_path = (LEADIN + '/state/' + self._host + '/ports/' +
                         str(data['tap_service']['port_id']))
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            port_sw_if_idx = port_info['iface_idx']
            old_bridge_domain_id = port_info['net_data']['bridge_domain_id']

            bridge_data = self.vppf.ensure_network_on_host(physnet,
                                                           network_type,
                                                           data['taas_id'])
            self.vppf.vpp.bridge_enable_flooding(
                bridge_data['bridge_domain_id'])
            self.vppf.vpp.add_to_bridge(bridge_data['bridge_domain_id'],
                                        port_sw_if_idx)

            props = {"ts": data,
                     "service_bridge": bridge_data,
                     "port": {"iface_idx": port_sw_if_idx,
                              "bridge_domain_id": old_bridge_domain_id}}

            self.etcd_client.write(self._state_key_space +
                                   '/%s' % tap_service_id,
                                   jsonutils.dumps(props))
        except etcd.EtcdKeyNotFound:
            pass

    def removed(self, key):
        # Removing key == desire to unbind
        try:
            # rebind iface to appropriate bridge
            taas_path = self._state_key_space + '/' + key
            tap_service_info = jsonutils.loads(
                self.etcd_client.read(taas_path).value)

            physnet = tap_service_info['service_bridge']['physnet']
            net_type = tap_service_info['service_bridge']['network_type']
            seg_id = tap_service_info['service_bridge']['segmentation_id']
            self.vppf.delete_network_on_host(physnet, net_type, seg_id)

            # put back the port to the old bridge
            self.vppf.vpp.add_to_bridge(
                tap_service_info['port']['bridge_domain_id'],
                tap_service_info['port']['iface_idx'])
            self.etcd_client.delete(taas_path)
        except etcd.EtcdKeyNotFound:
            # Gone is fine, if we didn't delete it
            # it's no problem
            pass


class TaasFlowAgentWatcher(etcdutils.EtcdChangeWatcher):
    path = 'taas_flow'

    def __init__(self, host, etcd_client_factory, vppf):
        self._node_key_space = LEADIN + '/nodes/%s/%s' % (host, self.path)
        self._state_key_space = LEADIN + \
            '/state_taas/%s/%s' % (host, self.path)
        self.etcd_client = etcd_client_factory.client()
        self.vppf = vppf
        self._host = host
        etcd_helper = etcdutils.EtcdHelper(self.etcd_client)
        etcd_helper.ensure_dir(self._node_key_space)
        etcd_helper.ensure_dir(self._state_key_space)
        self.iputils = ip_lib.IPWrapper()
        super(TaasFlowAgentWatcher, self).__init__(self.etcd_client,
                                                   self.path,
                                                   self._node_key_space)

    def added(self, key, value):
        # Create or update == bind
        flow_id = key
        data = jsonutils.loads(value)
        # data = value

        taas_id = data['taas_id']
        direction = data['tap_flow']['direction']

        port_path = (LEADIN + '/nodes/' + self._host + '/ports/' +
                     str(data['tap_flow']['source_port']))
        try:
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            physnet = port_info['physnet']
            network_type = port_info['network_type']
            # Need to put the tapped packets in a dedicated VLAN
            network_type = 'vlan'

            port_path = (LEADIN + '/state/' + self._host + '/ports/' +
                         str(data['tap_flow']['source_port']))
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            source_port_idx = port_info['iface_idx']

            # get/create a numbered bridge domain for the service

            service_bridge = self.vppf.ensure_network_on_host(
                physnet, network_type, taas_id)
            service_bridge_id = service_bridge['bridge_domain_id']
            self.vppf.vpp.bridge_enable_flooding(service_bridge_id)

            # Check Span direction
            if direction == 'IN':
                direction = 1
            elif direction == 'OUT':
                direction = 2
            else:
                direction = 3
            # Check if the tap flow is located in the same node
            # as the tap service
            tap_srv_id = data['tap_flow']['tap_service_id']
            port_path = (LEADIN + '/state_taas/' + self._host +
                         '/taas_service/' + tap_srv_id)
            try:
                srv_port_info = jsonutils.loads(
                    self.etcd_client.read(port_path).value)
                srv_port_idx = srv_port_info['port']['iface_idx']
                # Local Span
                dst_idx = srv_port_idx
                remote_span = False
                self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                    srv_port_idx,
                                                    direction)
            except etcd.EtcdKeyNotFound:
                # Remote Span
                srv_uplink_idx = service_bridge['if_uplink_idx']
                dst_idx = srv_uplink_idx
                remote_span = True
                self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                    srv_uplink_idx,
                                                    direction)

            # Set the tap_flow state in etcd
            data = {"tf": data,
                    "service_bridge": service_bridge,
                    "port_idx": source_port_idx,
                    'dst_idx': dst_idx,
                    'remote_span': remote_span
                    }
            self.etcd_client.write(self._state_key_space +
                                   '/%s' % flow_id,
                                   jsonutils.dumps(data))
        except etcd.EtcdKeyNotFound:
            pass

    def removed(self, key):
        # Removing key == desire to unbind
        flow_id = key
        try:
            taas_path = self._state_key_space + '/' + key
            tap_flow_info = jsonutils.loads(
                self.etcd_client.read(taas_path).value)

            dst_idx = tap_flow_info['dst_idx']
            remote_span = tap_flow_info['remote_span']
            self.vppf.vpp.disable_port_mirroring(tap_flow_info['port_idx'],
                                                 dst_idx)

            if remote_span:
                service_bridge = tap_flow_info['service_bridge']
                # service_bridge_id = service_bridge['bridge_domain_id']

                physnet = service_bridge['physnet']
                net_type = service_bridge['network_type']
                seg_id = service_bridge['segmentation_id']
                # check if the local service bridge needs to be removed
                spans = self.vppf.vpp.dump_port_mirroring()
                cnt = 0
                for sp in spans:
                    if sp.sw_if_index_to == dst_idx:
                        cnt += 1
                if cnt == 0:
                    self.vppf.delete_network_on_host(physnet, net_type, seg_id)

            self.etcd_client.delete(self._state_key_space +
                                    '/%s' % flow_id)
        except etcd.EtcdKeyNotFound:
            # Gone is fine, if we didn't delete it
            # it's no problem
            pass


class TaasVPPAgentExtension(VPPAgentExtensionBase):
    def initialize(self, manager):
        pass

    def run(self, host, client_factory, vpp_forwarder, gthread_pool):
        self.taas_service_watcher = TaasServiceAgentWatcher(host,
                                                            client_factory,
                                                            vpp_forwarder)
        self.taas_flow_watcher = TaasFlowAgentWatcher(host,
                                                      client_factory,
                                                      vpp_forwarder)
        gthread_pool.spawn(self.taas_service_watcher.watch_forever)
        gthread_pool.spawn(self.taas_flow_watcher.watch_forever)
