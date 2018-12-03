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
import ipaddress
import re
import sys

from networking_vpp.compat import plugin_constants
from networking_vpp import constants as nvpp_const
from networking_vpp import etcdutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils


LOG = logging.getLogger(__name__)

# A GPE constant
# A name for a GPE locator-set, which is a set of underlay interface indexes
gpe_lset_name = nvpp_const.GPE_LSET_NAME
LEADIN = nvpp_const.LEADIN


# TODO(onong): move to common file in phase 2
def ipnet(ip):
    return ipaddress.ip_network(six.text_type(ip))


def ipaddr(ip):
    return ipaddress.ip_address(six.text_type(ip))


def ipint(ip):
    return ipaddress.ip_interface(six.text_type(ip))


class GPEForwarder(object):
    """Provides methods for programming GPE functions in VPP."""

    def __init__(self,
                 vppf):
        # VPPForwarder
        self.vppf = vppf
        self.vpp = vppf.vpp
        # This is the address we'll use if we plan on broadcasting
        # vxlan packets
        # GPE underlay IP address/mask
        self.gpe_src_cidr = cfg.CONF.ml2_vpp.gpe_src_cidr
        # Name of the GPE physnet uplink and its address
        self.gpe_locators = cfg.CONF.ml2_vpp.gpe_locators
        # Will be set when we ensure GPE link
        self.gpe_underlay_addr = None
        # keeps track of gpe locators and mapping info
        self.gpe_map = {'remote_map': {}}

    def ensure_gpe_link(self):
        """Ensures that the GPE uplink interface is present and configured.

        Returns:-
        The software_if_index of the GPE uplink functioning as the underlay
        """
        intf, if_physnet = self.vppf.get_if_for_physnet(self.gpe_locators)
        LOG.debug('Setting GPE underlay attachment interface: %s',
                  intf)
        if if_physnet is None:
            LOG.error('Cannot create a GPE network because the gpe_'
                      'locators config value:%s is broken. Make sure this '
                      'value is set to a valid physnet name used as the '
                      'GPE underlay interface',
                      self.gpe_locators)
            sys.exit(1)
        self.vpp.ifup(if_physnet)
        # Set the underlay IP address using the gpe_src_cidr config option
        # setting in the config file
        LOG.debug('Configuring GPE underlay ip address %s on '
                  'interface %s', self.gpe_src_cidr, intf)
        (self.gpe_underlay_addr,
         self.gpe_underlay_mask) = self.gpe_src_cidr.split('/')
        physnet_ip_addrs = self.vpp.get_interface_ip_addresses(if_physnet)
        LOG.debug('Exising IP addresses %s', str(physnet_ip_addrs))
        cidr = (ipaddr(self.gpe_underlay_addr),
                int(self.gpe_underlay_mask))
        if cidr not in physnet_ip_addrs:
            self.vpp.set_interface_address(
                sw_if_index=if_physnet,
                is_ipv6=1 if ipnet(self.gpe_underlay_addr).version == 6 else 0,
                address_length=int(self.gpe_underlay_mask),
                address=self.vppf._pack_address(self.gpe_underlay_addr)
                )
        return (intf, if_physnet)

    def bridge_idx_for_segment(self, seg_id):
        """Generate a bridge domain index for GPE overlay networking

        Use the 65K namespace for GPE bridge-domains to avoid conflicts
        with other bridge domains and return a unique BD per network segment
        """
        return 65000 + seg_id

    def ensure_gpe_vni_to_bridge_mapping(self, seg_id, bridge_idx):
        # Add eid table mapping: vni to bridge-domain
        if (seg_id, bridge_idx) not in self.vpp.get_lisp_vni_to_bd_mappings():
            self.vpp.add_lisp_vni_to_bd_mapping(vni=seg_id,
                                                bridge_domain=bridge_idx)

    def delete_gpe_vni_to_bridge_mapping(self, seg_id, bridge_idx):
        # Remove vni to bridge-domain mapping in VPP if present
        if (seg_id, bridge_idx) in self.vpp.get_lisp_vni_to_bd_mappings():
            self.vpp.del_lisp_vni_to_bd_mapping(vni=seg_id,
                                                bridge_domain=bridge_idx)

    def delete_vni_from_gpe_map(self, seg_id):
        # Removes the VNI from the GPE Mapping
        self.gpe_map[gpe_lset_name]['vnis'].remove(seg_id)

    def clear_remote_gpe_mappings(self, segmentation_id):
        """Clear all GPE mac to seg_id remote mappings for the seg_id.

        When a segment is unbound from a host, all remote GPE mappings for
        that segment are cleared. Also any GPE ARP entries in the bridge
        domain are removed. As we no longer bind on this GPE segment,
        on this node, we need to clear all remote mappings and ARP data for
        segment for scalability reasons.
        """
        LOG.debug("Clearing all gpe remote mappings for VNI:%s",
                  segmentation_id)
        for mac_vni_tpl in self.gpe_map['remote_map'].keys():
            mac, vni = mac_vni_tpl
            # We also have (IP, VNI) tuples in remote_map. So, check if mac.
            if len(mac.split(':')) == 6 and segmentation_id == vni:
                self.delete_remote_gpe_mapping(vni, mac, None)
        # Clear any static GPE ARP entries in the bridge-domain for this VNI
        bridge_domain = self.bridge_idx_for_segment(segmentation_id)
        self.vpp.clear_lisp_arp_entries(bridge_domain)
        # Clear IPv6 NDP Entries
        self.vpp.clear_lisp_ndp_entries(bridge_domain)

    def ensure_remote_gpe_mapping(self, vni, mac, ip, remote_ip):
        """Ensures a remote GPE mapping

        A remote GPE mapping contains a remote mac-address of the instance,
        vni and the underlay ip address of the remote node (i.e. remote_ip)
        A remote GPE mapping also adds an ARP entry to the GPE control plane
        using the mac and ip address arguments. For Ipv6, an NDP entry is
        added.
        """
        # Add a remote-map only if a corresponding local map is not present
        # GPE complains if a remote and a local mapping is present for a mac
        lset_mapping = self.gpe_map[gpe_lset_name]
        if (mac, vni) not in self.gpe_map['remote_map'] and mac not in \
                lset_mapping['local_map']:
            is_ip4 = 1 if ipnet(remote_ip).version == 4 else 0
            remote_locator = {"is_ip4": is_ip4,
                              "priority": 1,
                              "weight": 1,
                              "addr": self.vppf._pack_address(remote_ip)
                              }
            self.vpp.add_lisp_remote_mac(mac, vni, remote_locator)
            self.gpe_map['remote_map'][(mac, vni)] = remote_ip
            # Add a LISP ARP/NDP entry for the remote VM's IPv4/v6 address.
            # If an ARP or NDP entry exists in the BD, replace it.
            bridge_domain = self.bridge_idx_for_segment(vni)
            if ip and ipnet(ip).version == 4:
                int_ip = int(ipaddr(ip))
                if not self.vpp.exists_lisp_arp_entry(bridge_domain, int_ip):
                    self.vpp.add_lisp_arp_entry(mac,
                                                bridge_domain,
                                                int_ip)
                else:
                    self.vpp.replace_lisp_arp_entry(mac,
                                                    bridge_domain,
                                                    int_ip)
            elif ip is not None:   # handle unaddressed port
                ip6 = self.vppf._pack_address(ip)
                if not self.vpp.exists_lisp_ndp_entry(bridge_domain, ip6):
                    self.vpp.add_lisp_ndp_entry(mac,
                                                bridge_domain,
                                                ip6)
                else:
                    self.vpp.replace_lisp_ndp_entry(mac,
                                                    bridge_domain,
                                                    ip6)

    def delete_remote_gpe_mapping(self, vni, mac, ip=None):
        """Delete a remote GPE vni to mac mapping."""
        if (mac, vni) in self.gpe_map['remote_map']:
            self.vpp.del_lisp_remote_mac(mac, vni)
            del self.gpe_map['remote_map'][(mac, vni)]
            # Delete the LISP ARP entry for remote instance's IPv4 address
            # if it's present and the IP address is present
            bridge_domain = self.bridge_idx_for_segment(vni)
            if ip and ipnet(ip).version == 4:
                int_ip = int(ipaddr(ip))
                if self.vpp.exists_lisp_arp_entry(bridge_domain, int_ip):
                    self.vpp.del_lisp_arp_entry(mac,
                                                bridge_domain,
                                                int_ip)
            elif ip is not None:
                ip6 = self.vppf._pack_address(ip)
                if self.vpp.exists_lisp_ndp_entry(bridge_domain, ip6):
                    self.vpp.del_lisp_ndp_entry(mac,
                                                bridge_domain,
                                                ip6)

    def add_local_gpe_mapping(self, vni, mac):
        """Add a local GPE mapping between a mac and vni."""
        lset_mapping = self.gpe_map[gpe_lset_name]
        # If a remote map exists, clear it as local map takes precedence
        # GPE complains, if a local and remote EID maps
        # are simultaneously present for the same MAC address.
        LOG.debug('Adding vni %s to gpe_map', vni)
        lset_mapping['vnis'].add(vni)
        if (mac, vni) in self.gpe_map['remote_map']:
            LOG.debug('Clearing mac, vni (%s, %s) from the remote-gpe-map '
                      'before adding a local mapping', mac, vni)
            self.delete_remote_gpe_mapping(vni, mac)
        if mac not in lset_mapping['local_map']:
            self.vpp.add_lisp_local_mac(mac, vni, gpe_lset_name)
            lset_mapping['local_map'][mac] = vni

    def delete_local_gpe_mapping(self, vni, mac):
        lset_mapping = self.gpe_map[gpe_lset_name]
        if mac in lset_mapping['local_map']:
            self.vpp.del_lisp_local_mac(mac, vni, gpe_lset_name)
            del self.gpe_map[gpe_lset_name]['local_map'][mac]

    def ensure_gpe_underlay(self):
        """Ensures that the GPE locator and locator sets are present in VPP

        A locator interface in GPE functions as the underlay attachment point
        This method will ensure that the underlay is programmed correctly for
        GPE to function properly

        Returns :- A list of locator sets
        [{'locator_set_name': <ls_set_name>,
         'locator_set_index': <ls_index>,
         'sw_if_idxs': []
        }]
        """
        # Check if any exsiting GPE underlay (a.k.a locator) is present in VPP
        # Read existing loctor-sets and locators in VPP by name
        locators = self.vpp.get_lisp_local_locators(gpe_lset_name)
        # Create a new GPE locator set if the locator does not exist
        if not locators:
            LOG.debug('Creating GPE locator set %s', gpe_lset_name)
            self.vpp.add_lisp_locator_set(gpe_lset_name)
        _, if_physnet = self.ensure_gpe_link()
        # Add the underlay interface to the locator set
        LOG.debug('Adding GPE locator for interface %s to locator-'
                  'set %s', if_physnet, gpe_lset_name)
        # Remove any stale locators from the locator set, which may
        # be due to a configuration change
        locator_indices = locators[0]['sw_if_idxs'] if locators else []
        for sw_if_index in locator_indices:
            if sw_if_index != if_physnet:
                self.vpp.del_lisp_locator(
                    locator_set_name=gpe_lset_name,
                    sw_if_index=sw_if_index)
        # Add the locator interface to the locator set if not present
        if not locators or if_physnet not in locator_indices:
            self.vpp.add_lisp_locator(
                locator_set_name=gpe_lset_name,
                sw_if_index=if_physnet
                )
        return self.vpp.get_lisp_local_locators(gpe_lset_name)

    def load_gpe_mappings(self):
        """Construct GPE locator mapping data structure in the VPP Forwarder.

        Read the locator and EID table mapping data from VPP and construct
        a gpe mapping for all existing local and remote end-point identifiers

        gpe_map: {'<locator_set_name>': {'locator_set_index': <index>,
                                              'sw_if_idxs' : set([<index>]),
                                              'vnis' : set([<vni>]),
                                              'local_map' : {<mac>: <vni>},
                        'remote_map' :  {<(mac, vni)> : <remote_ip>}
                       }
        """
        # First enable lisp
        LOG.debug("Enabling LISP GPE within VPP")
        self.vpp.lisp_enable()
        LOG.debug("Querying VPP to create a LISP GPE lookup map")
        # Ensure that GPE underlay locators are present and configured
        locators = self.ensure_gpe_underlay()
        LOG.debug('GPE locators %s for locator set %s',
                  locators, gpe_lset_name)
        # [ {'is_local':<>, 'locator_set_index':<>, 'mac':<>, 'vni':<>},.. ]
        # Load any existing MAC to VNI mappings
        eids = self.vpp.get_lisp_eid_table()
        LOG.debug('GPE eid table %s', eids)
        # Construct the GPE map from existing locators and mappings within VPP
        for locator in locators:
            data = {'locator_set_index': locator['locator_set_index'],
                    'sw_if_idxs': set(locator['sw_if_idxs']),
                    'vnis': set([val['vni'] for val in eids if
                                val['locator_set_index'] == locator[
                                    'locator_set_index']]),
                    'local_map': {val['mac']: val['vni'] for val
                                  in eids if val['is_local'] and
                                  val['locator_set_index'] == locator[
                                      'locator_set_index']}
                    }
            self.gpe_map[locator['locator_set_name']] = data
        # Create the remote GPE: mac-address to underlay lookup mapping
        self.gpe_map['remote_map'] = {
            (val['mac'], val['vni']): self.vpp.get_lisp_locator_ip(val[
                'locator_set_index']) for val in eids if not val['is_local']
            }
        LOG.debug('Successfully created a GPE lookup map by querying vpp %s',
                  self.gpe_map)

GPE_KEY_SPACE = LEADIN + "/global/networks/gpe"


class GpeListener(object):
    """Listen to and update etcd for GPE functions."""

    def __init__(self, etcd_listener):
        self.vppf = etcd_listener.vppf
        # GPE forwarder
        self.gpe = self.vppf.gpe
        self.client_factory = etcd_listener.client_factory
        self.host = etcd_listener.host
        self.gpe_locators = cfg.CONF.ml2_vpp.gpe_locators
        self.ensure_gpe_dir()
        self.gpe.load_gpe_mappings()

    def ensure_gpe_dir(self):
        etcd_client = self.client_factory.client()
        etcd_helper = etcdutils.EtcdHelper(etcd_client)
        etcd_helper.ensure_dir(GPE_KEY_SPACE)

    def is_valid_remote_map(self, vni, host):
        """Return True if the remote map is valid else False.

        A remote mapping is valid only if we bind a port on the vni
        Ignore all the other remote mappings as the host doesn't care
        """
        if host != self.host and vni in self.gpe.gpe_map[gpe_lset_name][
            'vnis']:
            return True
        else:
            return False

    def fetch_remote_gpe_mappings(self, vni):
        """Fetch and add all remote mappings from etcd for the vni

        Thread-safe: creates its own client every time
        """
        key_space = GPE_KEY_SPACE + "/%s" % vni
        LOG.debug("Fetching remote gpe mappings for vni:%s", vni)
        try:
            rv = etcdutils.json_writer(self.client_factory.client()).read(
                key_space, recursive=True)

            for child in rv.children:
                m = re.match(key_space + '/([^/]+)' + '/([^/]+)' + '/([^/]+)',
                             child.key)
                if m:
                    hostname = m.group(1)
                    mac = m.group(2)
                    ip = m.group(3)
                    if self.is_valid_remote_map(vni, hostname):
                        self.gpe.ensure_remote_gpe_mapping(vni, mac, ip,
                                                           child.value)
        except etcd.EtcdKeyNotFound:
            # The remote gpe key is not found. The agent may not have
            # added it to etcd yet. We will be told to read it later.
            # Continue and don't exit.
            pass
        except etcd.EtcdException as e:
            # Error log any other etcd exception
            LOG.error("Etcd exception %s while fetching GPE mappings", e)
            LOG.exception("etcd exception in fetch-gpe-mappings")
            # TODO(najoy): Handle other etcd GPE exceptions and deal with
            # what will retry if a failure happens

    def update_router_gpe_mappings(self):
        """Update GPE for VXLAN bound router ports upon HA state transitions.

        During a router HA state transitions, it is required to update its
        local and remote GPE mappings. When a master router becomes backup,
        remove its local and remote GPE mappings and when a backup router
        becomes master, add a remote and local GPE mapping.
        """
        router_ports = dict(self.vppf.router_interfaces)
        # Merge all known internal and external router ports
        router_ports.update(self.vppf.router_external_interfaces)
        for port in router_ports:
            data = router_ports[port]
            vxlan_bound = data['net_type'] == plugin_constants.TYPE_VXLAN
            seg_id = data['segmentation_id']
            mac_addr = data['mac_address']
            ip_addr = data['gateway_ip']
            # Master -->
            Backup state transiiton
            # Delete local GPE mapping as we no longer own this mac-address
            # Delete etcd GPE GPE mapping to let other router's know
            if vxlan_bound and not self.vppf.router_state:
                LOG.debug("GPE bound router port becoming BACKUP")
                self.gpe.delete_local_gpe_mapping(seg_id, mac_addr)
                LOG.debug('Deleted local GPE mapping for segment %s '
                          'and mac-address %s', seg_id, mac_addr)
                self.delete_etcd_gpe_remote_mapping(seg_id, mac_addr)
                LOG.debug('Deleted etcd GPE mapping for segment %s '
                          'and mac-address %s', seg_id, mac_addr)
            # Backup --> Master state transition
            # Delete any GPE remote-mappings in our CP because we own the mac
            # Add a local mapping and establish a remote mapping in etcd to
            # communicate the state transition to all routers
            elif vxlan_bound and self.vppf.router_state:
                LOG.debug("GPE bound router port becoming MASTER")
                self.gpe.delete_remote_gpe_mapping(seg_id,
                                                   mac_addr, ip_addr)
                LOG.debug('Deleted remote GPE mapping for segment %s '
                          'mac-address %s and ip_addr %s',
                          seg_id, mac_addr, ip_addr)
                self.gpe.add_local_gpe_mapping(seg_id, mac_addr)
                LOG.debug('Added local GPE mapping for segment %s '
                          'and mac-address %s', seg_id, mac_addr)
                self.add_etcd_gpe_remote_mapping(seg_id, mac_addr, ip_addr)
                LOG.debug('Added etcd GPE remote mapping for segment %s '
                          'mac-address %s and ip_addr %s',
                          seg_id, mac_addr, ip_addr)
                self.ensure_gpe_remote_mappings(seg_id)
                LOG.debug("Ensured GPE remote mappings for segment %s",
                          seg_id)

    def add_etcd_gpe_remote_mapping(self, segmentation_id, mac_address, ip):
        """Create a remote GPE overlay to underlay mapping

        Overlay = mac_address + ip_address of the VM's port
        Underlay = IP address of the VPP's underlay interface
        """
        underlay_ip = self.gpe.gpe_underlay_addr
        gpe_key = GPE_KEY_SPACE + '/%s/%s/%s' % (
            segmentation_id, self.host, ip)
        gpe_data = {'mac': mac_address, 'host': underlay_ip}
        LOG.debug('Writing GPE key to etcd %s with gpe_data %s',
                  gpe_key, gpe_data)
        etcdutils.json_writer(self.client_factory.client()).write(
            gpe_key, gpe_data)

    def delete_etcd_gpe_remote_mapping(self, segmentation_id, mac_address):
        """Delete a remote GPE overlay to underlay mapping."""
        gpe_dir = GPE_KEY_SPACE + '/%s/%s' % (segmentation_id, self.host)

        def get_child_keys():
            child_keys = etcdutils.json_writer(
                self.client_factory.client()).read(gpe_dir, recursive=True)
            return child_keys

        for result in get_child_keys().children:
            # TODO(najoy): Fix the type of result. It must be a
            # ParsedEtcdResult that works with signed keys instead
            # of the EtcdResult, and json.loads is not required.
            data = jsonutils.loads(result.value)
            if data['mac'] == mac_address:
                etcdutils.json_writer(self.client_factory.client()
                                      ).delete(result.key)
        # Delete the etcd directory if it's empty
        if len(list(get_child_keys().children)) == 1:
            for result in get_child_keys().children:
                if result.dir:
                    etcdutils.json_writer(
                        self.client_factory.client()).delete(result.key)

    def ensure_gpe_remote_mappings(self, segmentation_id):
        """Ensure all the remote GPE mappings are present in VPP

        Ensures the following:
        1) The bridge domain exists for the segmentation_id
        2) A segmentation_id to bridge-domain mapping is present
        3) All remote overlay to underlay mappings are fetched from etcd and
        added corresponding to this segmentation_id

        Arguments:-
        segmentation_id :- The VNI for which all remote overlay (MAC) to
        underlay mappings are fetched from etcd and ensured in VPP
        """
        lset_data = self.gpe.gpe_map[gpe_lset_name]
        # Fetch and add remote mappings only for "new" segments that we do
        # not yet know of, but will be binding to shortly as requested by ML2
        if segmentation_id not in lset_data['vnis']:
            lset_data['vnis'].add(segmentation_id)
            bridge_idx = self.gpe.bridge_idx_for_segment(segmentation_id)
            self.vppf.ensure_bridge_domain_in_vpp(bridge_idx)
            self.gpe.ensure_gpe_vni_to_bridge_mapping(segmentation_id,
                                                      bridge_idx)
            self.fetch_remote_gpe_mappings(segmentation_id)

    def physnet(self):
        """Get physnet name for port binding records.

        The GPE physnet stored is the locator ID, as VXLAN
        physnets are not useful.
        """
        # TODO(ijw): We should check, not override, the passed-in physnet.
        return cfg.CONF.ml2_vpp.gpe_locators

    def spawn_watchers(self, pool, heartbeat, data):
        LOG.debug("Spawning gpe_watcher")
        pool.spawn(GpeWatcher(self.client_factory.client(),
                              'gpe_watcher',
                              GPE_KEY_SPACE,
                              heartbeat=heartbeat,
                              data=data).watch_forever)


class GpeWatcher(etcdutils.EtcdChangeWatcher):
    """Etcd key watcher for GPE-specific information."""

    def do_tick(self):
        pass

    def parse_key(self, gpe_key):
        m = re.match('([^/]+)' + '/([^/]+)' + '/([^/]+)',
                     gpe_key)
        vni, hostname, ip = None, None, None
        if m:
            vni = int(m.group(1))
            hostname = m.group(2)
            ip = m.group(3)
        return (vni, hostname, ip)

    def added(self, gpe_key, value):
        # gpe_key format is "vni/hostname/ip"
        # gpe_value format is {'mac':<mac>, 'host':<underlay_ip>}
        vni, hostname, ip = self.parse_key(gpe_key)
        if (vni and hostname and ip and
                self.data.gpe_listener.is_valid_remote_map(vni, hostname)):
            data = jsonutils.loads(value)
            remote_ip = data['host']
            # Add only if remote_ip != my_underlay_ip
            if remote_ip != self.data.vppf.gpe.gpe_underlay_addr:
                LOG.debug("gpeWatcher adding remote-map for vni:%s, mac:%s, "
                          "ip:%s to the underlay %s",
                          vni, data['mac'], ip, remote_ip)
                # TODO(ijw): tie the GPE watcher more directly to its
                # dataplane functions rather than going via
                # EtcdListener
                self.data.vppf.gpe.ensure_remote_gpe_mapping(
                    vni=vni,
                    mac=data['mac'],
                    ip=ip,
                    remote_ip=remote_ip)
                self.data.vppf.gpe.gpe_map['remote_map'][(ip, vni)] = data[
                    'mac']

    def removed(self, gpe_key):
        vni, hostname, ip = self.parse_key(gpe_key)
        if (vni and hostname and ip and
                self.data.gpe_listener.is_valid_remote_map(vni, hostname)):
            mac = self.data.vppf.gpe.gpe_map['remote_map'].get((ip, vni))
            if mac:
                # TODO(ijw): tie the GPE watcher more directly to its
                # dataplane functions rather than going via
                # EtcdListener
                self.data.vppf.gpe.delete_remote_gpe_mapping(
                    vni=vni,
                    mac=mac,
                    ip=ip)
                del self.data.vppf.gpe.gpe_map['remote_map'][(ip, vni)]
