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
# import json
# import time
from networking_vpp.agent.server import LEADIN
from networking_vpp import etcdutils
# import networking_vpp.agent.vpp
import neutron.agent.linux.ip_lib as ip_lib
from oslo_serialization import jsonutils
from pprint import pprint


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
        pprint(data)
        port_path = (LEADIN + '/nodes/' + self._host + '/ports/' +
                     str(data['tap_service']['port_id']))
        port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
        physnet = port_info['physnet']
        network_type = port_info['network_type']

        # Need to put the tapped packets in a dedicated VLAN
        if network_type == 'flat':
            network_type = 'vlan'

        port_path = (LEADIN + '/state/' + self._host + '/ports/' +
                     str(data['tap_service']['port_id']))
        port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
        port_sw_if_idx = port_info['iface_idx']
        old_bridge_domain_id = port_info['net_data']['bridge_domain_id']

        bridge_data = self.vppf.ensure_network_on_host(physnet,
                                                       network_type,
                                                       data['taas_id'])
        pprint(bridge_data)
        self.vppf.vpp.bridge_enable_broadcast(bridge_data['bridge_domain_id'])
        self.vppf.vpp.add_to_bridge(bridge_data['bridge_domain_id'],
                                    port_sw_if_idx)

        props = {"ts": data,
                 "service_bridge": bridge_data,
                 "port": {"iface_idx": port_sw_if_idx,
                          "bridge_domain_id": old_bridge_domain_id}}

        self.etcd_client.write(self._state_key_space +
                               '/%s' % tap_service_id,
                               jsonutils.dumps(props))
        pprint(props)

    def removed(self, key):
        # Removing key == desire to unbind
        pprint('TaasService delete "%s"' % (key))
        try:
            # rebind iface to appropriate bridge
            taas_path = self._state_key_space + '/' + key
            pprint(taas_path)
            tap_service_info = jsonutils.loads(
                self.etcd_client.read(taas_path).value)
            pprint(tap_service_info)

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
        pprint(data)

        taas_id = data['taas_id']
        direction = data['tap_flow']['direction']

        port_path = (LEADIN + '/nodes/' + self._host + '/ports/' +
                     str(data['tap_flow']['source_port']))
        port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
        physnet = port_info['physnet']
        network_type = port_info['network_type']
        # Need to put the tapped packets in a dedicated VLAN
        if network_type == 'flat':
            network_type = 'vlan'

        port_path = (LEADIN + '/state/' + self._host + '/ports/' +
                     str(data['tap_flow']['source_port']))
        port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
        source_port_idx = port_info['iface_idx']

        # get/create a numbered bridge domain for the service

        service_bridge = self.vppf.ensure_network_on_host(
            physnet, network_type, taas_id)
        service_bridge_id = service_bridge['bridge_domain_id']
        self.vppf.vpp.bridge_enable_broadcast(service_bridge_id)

        # Check if the host_interface has already been created.
        # create the host interface

        itf_nameA = "veth_%s_%d_A" % (str(flow_id[:5]), service_bridge_id)
        itf_nameB = "veth_%s_%d_B" % (str(flow_id[:5]), service_bridge_id)
        lx_itfs = self.iputils.add_veth(itf_nameA, itf_nameB)
        lx_itfs[0].link.set_up()
        lx_itfs[1].link.set_up()
        itfA_idx = self.vppf.vpp.create_host_interface(itf_nameA)
        itfB_idx = self.vppf.vpp.create_host_interface(itf_nameB)
        self.vppf.vpp.ifup(itfA_idx)
        self.vppf.vpp.ifup(itfB_idx)
        self.vppf.vpp.add_to_bridge(service_bridge_id, itfB_idx)

        if direction == 'IN':
            direction = 1
        elif direction == 'OUT':
            direction = 2
        else:
            direction = 3
        self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                            itfA_idx,
                                            direction)
        data = {"tf": data,
                "service_bridge": service_bridge,
                "port_idx": source_port_idx,
                "itfA_idx": itfA_idx,
                }

        self.etcd_client.write(self._state_key_space +
                               '/%s' % flow_id,
                               jsonutils.dumps(data))

    def removed(self, key):
        # Removing key == desire to unbind
        flow_id = key
        try:
            taas_path = self._state_key_space + '/' + key
            tap_flow_info = jsonutils.loads(
                self.etcd_client.read(taas_path).value)

            itfA_idx = tap_flow_info['itfA_idx']
            self.vppf.vpp.disable_port_mirroring(tap_flow_info['port_idx'],
                                                 itfA_idx)

            service_bridge = tap_flow_info['service_bridge']
            service_bridge_id = service_bridge['bridge_domain_id']
            itf_nameA = "veth_%s_%d_A" % (str(flow_id[:5]), service_bridge_id)
            itf_nameB = "veth_%s_%d_B" % (str(flow_id[:5]), service_bridge_id)
            self.vppf.vpp.delete_host_interface(itf_nameA)
            self.vppf.vpp.delete_host_interface(itf_nameB)

            self.iputils.del_veth(itf_nameA)

            physnet = service_bridge['physnet']
            net_type = service_bridge['network_type']
            seg_id = service_bridge['segmentation_id']
            # check if the local service bridge needs to be removed
            itfs = self.vppf.vpp.get_ifaces_in_bridge_domain(service_bridge_id)
            if (net_type == 'vxlan' and len(itfs) == 0) or (len(itfs) <= 1):
                self.vppf.delete_network_on_host(physnet, net_type, seg_id)

            self.etcd_client.delete(self._state_key_space +
                                    '/%s' % flow_id)
        except etcd.EtcdKeyNotFound:
            # Gone is fine, if we didn't delete it
            # it's no problem
            pass
