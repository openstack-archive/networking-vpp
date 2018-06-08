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
from ipaddress import ip_network
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
            if network_type != 'vxlan':
                network_type = 'vlan'

            port_path = (LEADIN + '/state/' + self._host + '/ports/' +
                         str(data['tap_service']['port_id']))
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            port_sw_if_idx = port_info['iface_idx']
            old_bridge_domain_id = port_info['net_data']['bridge_domain_id']

            if network_type == 'vxlan':
                bd_idx = data['taas_id'] + 64000
                self.vppf.ensure_bridge_domain_in_vpp(bd_idx)
                bridge_data = {
                    'physnet': physnet,
                    'if_physnet': -1,
                    'bridge_domain_id': bd_idx,
                    'network_type': network_type,
                    'segmentation_id': data['taas_id'],
                }

            else:
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

            # put back the port to the old bridge
            self.vppf.vpp.add_to_bridge(
                tap_service_info['port']['bridge_domain_id'],
                tap_service_info['port']['iface_idx'])

            physnet = tap_service_info['service_bridge']['physnet']
            net_type = tap_service_info['service_bridge']['network_type']
            seg_id = tap_service_info['service_bridge']['segmentation_id']
            if net_type == 'vxlan':
                bd_idx = tap_service_info['service_bridge']['bridge_domain_id']
                self.vppf.vpp.delete_bridge_domain(bd_idx)
            else:
                self.vppf.delete_network_on_host(physnet, net_type, seg_id)

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

    def _find_port_idx(self, port_id, host):
        port_path = (LEADIN + '/state/' + host + '/ports/' +
                     str(port_id))
        try:
            port_info = jsonutils.loads(self.etcd_client.read(port_path).value)
            port_idx = port_info['iface_idx']
        except etcd.EtcdKeyNotFound:
            port_idx = -1
        return port_idx

    def _create_vxlan_tunnel(self, dst_adr, vni):
        vxtuns = self.vppf.vpp.get_vxlan_tunnels()
        for (tvni, tidx) in vxtuns:
            if vni == tvni:
                return tidx

        self.vppf.ensure_gpe_link()
        src_adr = self.vppf.gpe_underlay_addr
        if ip_network(unicode(src_adr)).version == 6:
            is_ipv6 = 1
        else:
            is_ipv6 = 0
        idx = self.vppf.vpp.create_vxlan_tunnel(
            self.vppf._pack_address(src_adr),
            self.vppf._pack_address(dst_adr),
            is_ipv6,
            vni)
        return idx

    def _delete_vxlan_tunnel(self, dst_adr, vni):
        self.vppf.ensure_gpe_link()
        src_adr = self.vppf.gpe_underlay_addr
        if ip_network(unicode(src_adr)).version == 6:
            is_ipv6 = 1
        else:
            is_ipv6 = 0
        self.vppf.vpp.delete_vxlan_tunnel(
            self.vppf._pack_address(src_adr),
            self.vppf._pack_address(dst_adr),
            is_ipv6,
            vni)

    def _get_remote_addr(self, port_mac):
        self.vppf.load_gpe_mappings()
        remote_ip = ''
        for mac_vni_tpl in self.vppf.gpe_map['remote_map'].keys():
            mac, vni = mac_vni_tpl
            if mac == port_mac:
                remote_ip = self.vppf.gpe_map['remote_map'][(mac, vni)]
        return remote_ip

    def _get_nb_flow(self, tf_host, taas_id):
        num = 0
        watch_space = LEADIN + '/nodes/%s/taas_flow' % (tf_host)
        rv = self.etcd_client.read(watch_space,
                                   recursive=True)
        for f in rv.children:
            if f.value is not None:
                data = jsonutils.loads(f.value)
                if data['taas_id'] == taas_id:
                    num = num + 1

        return num

    def added(self, key, value):
        # Create or update == bind
        flow_id = key
        data = jsonutils.loads(value)
        # data = value

        taas_id = data['taas_id']
        direction = data['tap_flow']['direction']
        ts_host = data['ts_host']
        tf_host = data['tf_host']
        # Check Span direction
        if direction == 'IN':
            direction = 1
        elif direction == 'OUT':
            direction = 2
        else:
            direction = 3

        tap_srv_id = data['tap_flow']['tap_service_id']
        ts_path = (LEADIN + '/state_taas/' + ts_host +
                   '/taas_service/' + tap_srv_id)
        try:
            ts_info = jsonutils.loads(self.etcd_client.read(ts_path).value)
            network_type = ts_info['service_bridge']['network_type']
            physnet = ts_info['service_bridge']['physnet']

            if network_type != 'vxlan':
                network_type = 'vlan'

            # Check if tap flow and tap service are located in the same node
            # Local Span
            if ts_host == tf_host:
                source_port_idx = self._find_port_idx(
                    data['tap_flow']['source_port'], tf_host)
                srv_port_idx = ts_info['port']['iface_idx']
                # Local Span
                dst_idx = srv_port_idx
                self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                    srv_port_idx,
                                                    direction)
                # Set the tap_flow state in etcd
                data = {"tf": data,
                        "port_idx": source_port_idx,
                        'dst_idx': dst_idx,
                        'span_mode': 0,  # Local
                        'tfn': True
                        }
            # Remote Span via vlan
            elif network_type == 'vlan':
                if self._host == tf_host:
                    source_port_idx = self._find_port_idx(
                        data['tap_flow']['source_port'], tf_host)

                    # get/create a numbered bridge domain for the service

                    service_bridge = self.vppf.ensure_network_on_host(
                        physnet, network_type, taas_id)
                    service_bridge_id = service_bridge['bridge_domain_id']
                    self.vppf.vpp.bridge_enable_flooding(service_bridge_id)

                    # Remote Span
                    srv_uplink_idx = service_bridge['if_uplink_idx']
                    dst_idx = srv_uplink_idx
                    self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                        srv_uplink_idx,
                                                        direction)

                    # Set the tap_flow state in etcd
                    data = {"tf": data,
                            "service_bridge": service_bridge,
                            "port_idx": source_port_idx,
                            'dst_idx': dst_idx,
                            'span_mode': 1,  # vlan
                            'tfn': True
                            }
                else:
                    # Set the tap_flow state in etcd
                    data = {"tf": data,
                            'span_mode': 1,  # vlan
                            'tfn': False
                            }

            # Remote Span via vxlan
            else:
                if self._host == tf_host:
                    dst_adr = self._get_remote_addr(data['ts_port_mac'])
                else:
                    dst_adr = self._get_remote_addr(data['port_mac'])
                source_port_idx = self._find_port_idx(
                    data['tap_flow']['source_port'], tf_host)
                vni = taas_id
                tun_idx = self._create_vxlan_tunnel(dst_adr, vni)
                # source_port_idx = -1
                if self._host == tf_host:
                    tfn = True
                    self.vppf.vpp.cross_connect(tun_idx, 0)
                    self.vppf.vpp.enable_port_mirroring(source_port_idx,
                                                        tun_idx,
                                                        direction)
                else:
                    tfn = False
                    bd_idx = taas_id + 64000
                    self.vppf.vpp.add_to_bridge(bd_idx,
                                                tun_idx)

                self.vppf.vpp.ifup(tun_idx)
                # Set the tap_flow state in etcd
                data = {"tf": data,
                        "dst_idx": tun_idx,
                        "port_idx": source_port_idx,
                        'span_mode': 2,  # vxlan
                        'tfn': tfn,
                        'dst_adr': dst_adr,
                        'vni': vni
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

            span_mode = tap_flow_info['span_mode']
            tfn = tap_flow_info['tfn']
            if tfn:
                dst_idx = tap_flow_info['dst_idx']
                source_port_idx = tap_flow_info['port_idx']
                self.vppf.vpp.disable_port_mirroring(source_port_idx,
                                                     dst_idx)

            if span_mode == 1 and tfn:
                service_bridge = tap_flow_info['service_bridge']

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

            elif span_mode == 2:  # vxlan
                taas_id = tap_flow_info['tf']['taas_id']
                tf_host = tap_flow_info['tf']['tf_host']
                tf_nb = self._get_nb_flow(tf_host, taas_id)
                if tf_nb == 0:
                    if tfn is False:
                        self.vppf.vpp.delete_from_bridge(
                            tap_flow_info['dst_idx'])
                    vni = tap_flow_info['vni']
                    dst_adr = tap_flow_info['dst_adr']
                    self._delete_vxlan_tunnel(dst_adr, vni)

            self.etcd_client.delete(self._state_key_space +
                                    '/%s' % flow_id)
        except etcd.EtcdKeyNotFound:
            # Gone is fine, if we didn't delete it
            # it's no problem
            pass


# This watcher is needed to manage the out of order etcd messages
# (e.g when the agent is restarted)
class TaasPortAgentWatcher(etcdutils.EtcdChangeWatcher):
    path = 'taas_port'

    def __init__(self, host, etcd_client_factory, tsw, tfw):
        self._port_key_space = LEADIN + '/state/%s/ports' % (host)
        self.etcd_client = etcd_client_factory.client()
        self._host = host
        self._tsw = tsw
        self._tfw = tfw
        etcd_helper = etcdutils.EtcdHelper(self.etcd_client)
        etcd_helper.ensure_dir(self._port_key_space)
        super(TaasPortAgentWatcher, self).__init__(self.etcd_client,
                                                   self.path,
                                                   self._port_key_space)

    def _trigger_tap_service(self, key, value):
        self._tsw.added(key, value)

    def _trigger_tap_flow(self, key, value):
        self._tfw.added(key, value)

    def _check_etcd_taas(self, port_id):
        watch_space = LEADIN + '/nodes/%s/taas_service' % (self._host)
        rv = self.etcd_client.read(watch_space,
                                   recursive=True)
        tap_srv_lst = list()
        for f in rv.children:
            if f.value is not None:
                data = jsonutils.loads(f.value)
                if data['tap_service']['port_id'] == port_id:
                    tap_srv_lst.append(f.key)
                    self._trigger_tap_service(f.key, f.value)

        watch_space = LEADIN + '/nodes/%s/taas_flow' % (self._host)
        rv = self.etcd_client.read(watch_space,
                                   recursive=True)
        for f in rv.children:
            if f.value is not None:
                data = jsonutils.loads(f.value)
                if data['tap_flow']['source_port'] == port_id:
                    self._trigger_tap_flow(f.key, f.value)
                elif data['tap_flow']['tap_service_id'] in tap_srv_lst:
                    self._trigger_tap_flow(f.key, f.value)

    def added(self, key, value):
        self._check_etcd_taas(key)

    def removed(self, key):
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
        self.taas_port_watcher = TaasPortAgentWatcher(
            host,
            client_factory,
            self.taas_service_watcher,
            self.taas_flow_watcher)
        gthread_pool.spawn(self.taas_service_watcher.watch_forever)
        gthread_pool.spawn(self.taas_flow_watcher.watch_forever)
        gthread_pool.spawn(self.taas_port_watcher.watch_forever)
