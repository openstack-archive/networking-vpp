# Copyright (c) 2016 Cisco Systems, Inc.
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

# Note that it does *NOT* at this point have a persistent database, so
# restarting this process will make Gluon forget about every port it's
# learned, which will not do your system much good (the data is in the
# global 'backends' and 'ports' objects).  This is for simplicity of
# demonstration; we have a second codebase already defined that is
# written to OpenStack endpoint principles and includes its ORM, so
# that work was not repeated here where the aim was to get the APIs
# worked out.  The two codebases will merge in the future.

import binascii
import etcd
import eventlet
import json
import os
import re
import sys
import threading
import time
import vpp

from collections import defaultdict
from collections import namedtuple
from ipaddress import ip_address
from networking_vpp._i18n import _
from networking_vpp.agent import utils as nwvpp_utils
from networking_vpp import compat
from networking_vpp.compat import n_const
from networking_vpp import config_opts
from networking_vpp.etcdutils import EtcdWatcher
from networking_vpp.mech_vpp import SecurityGroup
from networking_vpp.mech_vpp import SecurityGroupRule
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)
eventlet.monkey_patch()
# A model of a bi-directional VPP ACL corresponding to a secgroup
VppAcl = namedtuple('VppAcl', ['in_idx', 'out_idx'])
# a Mapping of security groups to VPP ACLs
secgroups = {}     # secgroup_uuid: VppAcl(ingress_idx, egress_idx)
# TODO(najoy) Expose the below as a config option
# Enable stateful reflexive ACLs in VPP which adds automatic reverse rules
# When False, reverse rules are added by the vpp-agent and
# VPP does not maintain any session states
reflexive_acls = True
# Register security group option
security_group_opts = [
    cfg.BoolOpt('enable_security_group', default=True,
                help=_('Controls whether neutron security groups is enabled '
                       'Set it to false to disable security groups')),
    ]
cfg.CONF.register_opts(security_group_opts, 'SECURITYGROUP')
# config_opts is required to configure the options within it, but
# not referenced from here, so shut up tox:
assert config_opts

eventlet.monkey_patch()

######################################################################

# This mirrors functionality in Neutron so that we're creating a name
# that Neutron can find for its agents.

DEV_NAME_PREFIX = n_const.TAP_DEVICE_PREFIX

# Apply monkey patch if necessary
compat.monkey_patch()


def get_tap_name(uuid):
    return n_const.TAP_DEVICE_PREFIX + uuid[0:11]


def get_vhostuser_name(uuid):
    return os.path.join(cfg.CONF.ml2_vpp.vhost_user_dir, uuid)


######################################################################


class UnsupportedInterfaceException(Exception):
    pass


class VPPForwarder(object):

    def __init__(self,
                 physnets,  # physnet_name: interface-name
                 mac_age,
                 vxlan_src_addr=None,
                 vxlan_bcast_addr=None,
                 vxlan_vrf=None):
        self.vpp = vpp.VPPInterface(LOG)

        self.physnets = physnets

        self.mac_age = mac_age

        # This is the address we'll use if we plan on broadcasting
        # vxlan packets
        self.vxlan_bcast_addr = vxlan_bcast_addr
        self.vxlan_src_addr = vxlan_src_addr
        self.vxlan_vrf = vxlan_vrf
        # Used as a unique number for bridge IDs

        self.networks = {}      # (physnet, type, ID): datastruct
        self.interfaces = {}    # uuid: if idx
        # mac_ip acls do not support atomic replacement.
        # Here we create a mapping of sw_if_index to VPP ACL indices
        # so we can easily lookup the ACLs associated with the interface idx
        # sw_if_index: {"l34": [l34_acl_indxs], "l23": l23_acl_index }
        self.port_vpp_acls = defaultdict(dict)

        # key: sw if index in VPP; present when vhost-user is
        # connected and removed when we delete things.  May accumulate
        # any other VPP interfaces too, but that's harmless.
        self.iface_connected = set()

        self.vhost_ready_callback = None
        cb_event = self.vpp.CallbackEvents.VHOST_USER_CONNECT
        self.vpp.register_for_events(cb_event, self._vhost_ready_event)

    ########################################

    def _vhost_ready_event(self, iface):
        """Callback from VPP interface on vhostuser socket connection"""

        # TODO(ijw): messy and a bit specific to the VPP interface -
        # shouldn't be returning the API datastructure?
        LOG.debug("vhost online: %s", str(iface))
        self._notify_connected(iface.sw_if_index)

    def _notify_connected(self, sw_if_index):
        """Deal with newly active interfaces noticed by VPP

        Any interface that has been created and has also been
        connected to goes into the up state.  At this point, we can
        safely say that the VM is ready for traffic passing.

        When interacting with Nova, this usually indicates that the VM
        has been created and the vhost-user connection made.  We
        should send the notification only after the port has been
        created and the hypervisor has attached to it.  (You have to
        create the interface to be attached to but this checks for
        the data that's written on creation to be ready to avoid
        a race condition.)

        We may send multiple notifications to Nova if an interface
        disconnects and reconnects - this is harmless.
        """
        self.iface_connected.add(sw_if_index)

        if self.vhost_ready_callback:
            self.vhost_ready_callback(sw_if_index)

    def vhostuser_linked_up(self, sw_if_index):
        return sw_if_index in self.iface_connected

    ########################################

    def get_if_for_physnet(self, physnet):
        ifname = self.physnets.get(physnet, None)
        if ifname is None:
            LOG.error('Physnet %s requested but not in config',
                      physnet)
            return None, None
        ifidx = self.vpp.get_ifidx_by_name(ifname)
        if ifname is None:
            LOG.error('Physnet %s interface %s does not '
                      'exist in VPP', ifname)
            return None, None
        return ifname, ifidx

    def network_on_host(self, physnet, net_type, seg_id=None):
        """Find or create a network of the type required"""

        if (physnet, net_type, seg_id) not in self.networks:
            self.create_network_on_host(physnet, net_type, seg_id)
        return self.networks.get((physnet, net_type, seg_id), None)

    def create_network_on_host(self, physnet, net_type, seg_id):
        intf, ifidx = self.get_if_for_physnet(physnet)
        if intf is None:
            return None

        # TODO(ijw): bridge domains have no distinguishing marks.
        # VPP needs to allow us to name or label them so that we
        # can find them when we restart.  If we add an interface
        # to two bridges that will likely not do as required

        if net_type == 'flat':
            if_upstream = ifidx

            LOG.debug('Adding upstream interface-idx:%s-%s to bridge '
                      'for flat networking', intf, if_upstream)

        elif net_type == 'vlan':
            self.vpp.ifup(ifidx)

            LOG.debug('Adding upstream VLAN interface %s.%s '
                      'to bridge for vlan networking', intf, seg_id)
            if_upstream = self.vpp.get_ifidx_by_name('%s.%s' % (intf, seg_id))
            if if_upstream is None:
                if_upstream = self.vpp.create_vlan_subif(ifidx,
                                                         seg_id)
        # elif net_type == 'vxlan':
        #     # NB physnet not really used here
        #     if_upstream = \
        #         self.vpp.create_srcrep_vxlan_subif(self, self.vxlan_vrf,
        #                                            self.vxlan_src_addr,
        #                                            self.vxlan_bcast_addr,
        #                                            seg_id)
        else:
            raise Exception('network type %s not supported', net_type)

        self.vpp.ifup(if_upstream)

        # Out bridge IDs have one upstream interface in so we simply use
        # that ID as their domain ID
        self.vpp.create_bridge_domain(if_upstream, self.mac_age)

        self.vpp.add_to_bridge(if_upstream, if_upstream)
        self.networks[(physnet, net_type, seg_id)] = {
            'bridge_domain_id': if_upstream,
            'if_upstream': intf,
            'if_upstream_idx': if_upstream,
            'network_type': net_type,
            'segmentation_id': seg_id,
            'physnet': physnet,
        }

    def delete_network_on_host(self, physnet, net_type, seg_id=None):
        net = self.networks.get((physnet, net_type, seg_id), None)
        if net is not None:

            self.vpp.delete_bridge_domain(net['bridge_domain_id'])
            if net['network_type'] == 'vlan':
                ifidx = self.vpp.get_ifidx_by_name(net['if_upstream']
                                                   + '.' + str(seg_id))
                self.vpp.delete_vlan_subif(ifidx)

            self.networks.pop((physnet, net_type, seg_id))
        else:
            LOG.warning("Delete Network: network is unknown to agent")

    ########################################
    # stolen from LB driver
    def _bridge_exists_and_ensure_up(self, bridge_name):
        """Check if the bridge exists and make sure it is up."""
        br = ip_lib.IPDevice(bridge_name)
        br.set_log_fail_as_error(False)
        try:
            # If the device doesn't exist this will throw a RuntimeError
            br.link.set_up()
        except RuntimeError:
            return False
        return True

    def ensure_bridge(self, bridge_name):
        """Create a bridge unless it already exists."""
        # _bridge_exists_and_ensure_up instead of device_exists is used here
        # because there are cases where the bridge exists but it's not UP,
        # for example:
        # 1) A greenthread was executing this function and had not yet executed
        # "ip link set bridge_name up" before eventlet switched to this
        # thread running the same function
        # 2) The Nova VIF driver was running concurrently and had just created
        #    the bridge, but had not yet put it UP
        if not self._bridge_exists_and_ensure_up(bridge_name):
            bridge_device = bridge_lib.BridgeDevice.addbr(bridge_name)
            if bridge_device.setfd(0):
                return
            if bridge_device.disable_stp():
                return
            if bridge_device.disable_ipv6():
                return
            if bridge_device.link.set_up():
                return
        else:
            bridge_device = bridge_lib.BridgeDevice(bridge_name)
        return bridge_device

        # TODO(ijw): should be checking this all succeeded

    # end theft
    ########################################

    # TODO(njoy): make wait_time configurable
    # TODO(ijw): needs to be one thread for all waits
    def add_external_tap(self, device_name, bridge, bridge_name):
        """Add an externally created TAP device to the bridge

        Wait for the external tap device to be created by the DHCP agent.
        When the tap device is ready, add it to bridge Run as a thread
        so REST call can return before this code completes its
        execution.

        """
        wait_time = 60
        found = False
        while wait_time > 0:
            if ip_lib.device_exists(device_name):
                LOG.debug('External tap device %s found!',
                          device_name)
                LOG.debug('Bridging tap interface %s on %s',
                          device_name, bridge_name)
                if not bridge.owns_interface(device_name):
                    bridge.addif(device_name)
                else:
                    LOG.debug('Interface: %s is already added '
                              'to the bridge %s',
                              device_name, bridge_name)
                found = True
                break
            else:
                time.sleep(2)
                wait_time -= 2
        if not found:
            LOG.error('Failed waiting for external tap device:%s',
                      device_name)

    def create_interface_on_host(self, if_type, uuid, mac):
        if uuid in self.interfaces:
            LOG.debug('port %s repeat binding request - ignored', uuid)
        else:
            LOG.debug('binding port %s as type %s',
                      uuid, if_type)

            # TODO(ijw): naming not obviously consistent with
            # Neutron's naming
            name = uuid[0:11]
            bridge_name = 'br-' + name
            tap_name = 'tap' + name

            if if_type == 'maketap' or if_type == 'plugtap':
                if if_type == 'maketap':
                    iface_idx = self.vpp.create_tap(tap_name, mac)
                    props = {'name': tap_name}
                else:
                    int_tap_name = 'vpp' + name

                    props = {'bridge_name': bridge_name,
                             'ext_tap_name': tap_name,
                             'int_tap_name': int_tap_name}

                    LOG.debug('Creating tap interface %s with mac %s',
                              int_tap_name, mac)
                    iface_idx = self.vpp.create_tap(int_tap_name, mac)
                    # TODO(ijw): someone somewhere ought to be sorting
                    # the MTUs out
                    br = self.ensure_bridge(bridge_name)
                    # This is the external TAP device that will be
                    # created by an agent, say the DHCP agent later in
                    # time
                    t = threading.Thread(target=self.add_external_tap,
                                         args=(tap_name, br, bridge_name,))
                    t.start()
                    # This is the device that we just created with VPP
                    if not br.owns_interface(int_tap_name):
                        br.addif(int_tap_name)
            elif if_type == 'vhostuser':
                path = get_vhostuser_name(uuid)
                iface_idx = self.vpp.create_vhostuser(path, mac)
                props = {'path': path}
            else:
                raise UnsupportedInterfaceException(
                    'unsupported interface type')
            props['bind_type'] = if_type
            props['iface_idx'] = iface_idx
            props['mac'] = mac
            self.interfaces[uuid] = props
        return self.interfaces[uuid]

    def bind_interface_on_host(self, if_type, uuid, mac, physnet,
                               net_type, seg_id):
        # TODO(najoy): Need to send a return value so the ML2 driver
        # can raise an exception and prevent network creation (when
        # network_on_host returns None)

        net_data = self.network_on_host(physnet, net_type, seg_id)
        net_br_idx = net_data['bridge_domain_id']
        props = self.create_interface_on_host(if_type, uuid, mac)
        iface_idx = props['iface_idx']
        self.vpp.ifup(iface_idx)
        self.vpp.add_to_bridge(net_br_idx, iface_idx)
        props['net_data'] = net_data
        LOG.debug('Bound vpp interface with sw_idx:%s on '
                  'bridge domain:%s',
                  iface_idx, net_br_idx)
        return props

    def unbind_interface_on_host(self, uuid):
        if uuid not in self.interfaces:
            LOG.debug('unknown port %s unbinding request - ignored',
                      uuid)
        else:
            props = self.interfaces[uuid]
            iface_idx = props['iface_idx']

            LOG.debug('unbinding port %s, recorded as type %s',
                      uuid, props['bind_type'])

            # We no longer need this interface.  Specifically if it's
            # a vhostuser interface it's annoying to have it around
            # because the VM's memory (hugepages) will not be
            # released.  So, here, we destroy it.

            if props['bind_type'] == 'vhostuser':
                # remove port from bridge (sets to l3 mode) prior to deletion
                self.vpp.delete_from_bridge(iface_idx)
                self.vpp.delete_vhostuser(iface_idx)
                # Delete port from vpp_acl map if present
                if iface_idx in self.port_vpp_acls:
                    del self.port_vpp_acls[iface_idx]
                    LOG.debug("secgroup_watcher: Current port acl_vector "
                              "mappings %s" % str(self.port_vpp_acls))
            elif props['bind_type'] in ['maketap', 'plugtap']:
                # remove port from bridge (sets to l3 mode) prior to deletion
                self.vpp.delete_from_bridge(iface_idx)
                self.vpp.delete_tap(iface_idx)
                if props['bind_type'] == 'plugtap':
                    name = uuid[0:11]
                    bridge_name = 'br-' + name
                    bridge = bridge_lib.BridgeDevice(bridge_name)
                    if bridge.exists():
                        # These may fail, don't care much
                        try:
                            if bridge.owns_interface(props['int_tap_name']):
                                bridge.delif(props['int_tap_name'])
                            if bridge.owns_interface(props['ext_tap_name']):
                                bridge.delif(props['ext_tap_name'])
                            bridge.link.set_down()
                            bridge.delbr()
                        except Exception as exc:
                            LOG.debug(exc)
            else:
                LOG.error('Unknown port type %s during unbind',
                          props['bind_type'])
            self.interfaces.pop(uuid)

            # This interface is no longer connected if it's deleted
            self.iface_connected.remove(iface_idx)

            # Check if this is the last interface on host
            for interface in self.interfaces.values():
                if props['net_data'] == interface['net_data']:
                    break
            else:
                # Network is not used on this host, delete it
                net = props['net_data']
                self.delete_network_on_host(net['physnet'],
                                            net['network_type'],
                                            net['segmentation_id'])

    def _to_acl_rule(self, r, d, a=2):
        """Convert a SecurityGroupRule to VPP ACL rule.

        Arguments:
        r - SecurityGroupRule NamedTuple Object
        SecurityGroupRule = namedtuple(
                                'SecurityGroupRule',
                                 ['is_ipv6',
                                 'remote_ip_addr',
                                 'ip_prefix_len',
                                 'protocol',
                                 'port_min',
                                 'port_max'])
        d - Direction:  0 ==> ingress, 1 ==> egress
        a - Permit-Action: 1 == permit, 2 == reflexive;
        Default == 2
        Return: VPP ACL Rule
        """
        acl_rule = {}
        # If reflexive is False a = 1
        if not reflexive_acls:
            a = 1
        # Enable reflexive ACLs for all TCP/UDP and IP traffic
        elif reflexive_acls and r.protocol in [6, 17, 0]:
            a = 2
        else:
            a = 1  # Disable reflexive for other traffic such as ICMP etc.
        acl_rule['is_permit'] = a
        acl_rule['is_ipv6'] = r.is_ipv6
        acl_rule['proto'] = r.protocol
        # for ingress: secgroup remote_ip == Source IP
        # for egress: secgroup remote_ip == Destination IP
        # Port ranges are always destination port ranges for TCP/UDP
        # Set source port range to permit all ranges from 0 to 65535
        if d == 0:
            acl_rule['src_ip_addr'] = r.remote_ip_addr
            acl_rule['src_ip_prefix_len'] = r.ip_prefix_len
        else:
            acl_rule['dst_ip_addr'] = r.remote_ip_addr
            acl_rule['dst_ip_prefix_len'] = r.ip_prefix_len
        # Handle ICMP/ICMPv6
        if r.protocol in [1, 58]:
            if r.port_min == -1:  # All ICMP Types and Codes [0-255]
                acl_rule['srcport_or_icmptype_first'] = 0
                acl_rule['srcport_or_icmptype_last'] = 255
                acl_rule['dstport_or_icmpcode_first'] = 0
                acl_rule['dstport_or_icmpcode_last'] = 255
            else:  # port_min == ICMP Type and port_max == ICMP Code
                acl_rule['srcport_or_icmptype_first'] = r.port_min
                acl_rule['srcport_or_icmptype_last'] = r.port_min
                acl_rule['dstport_or_icmpcode_first'] = r.port_max
                acl_rule['dstport_or_icmpcode_last'] = r.port_max
        # Handle TCP/UDP protocols
        elif r.protocol in [6, 17]:
            acl_rule['dstport_or_icmpcode_first'] = r.port_min
            acl_rule['dstport_or_icmpcode_last'] = r.port_max
            # Allow all ranges for source ports
            acl_rule['srcport_or_icmptype_first'] = 0
            acl_rule['srcport_or_icmptype_last'] = 65535
        # Handle all protocols - All IPv4 and IPv6 TCP/UDP traffic
        elif r.protocol == 0:
            acl_rule['dstport_or_icmpcode_first'] = 0
            acl_rule['dstport_or_icmpcode_last'] = 65535
            acl_rule['srcport_or_icmptype_first'] = 0
            acl_rule['srcport_or_icmptype_last'] = 65535
        return acl_rule

    # Reverse rules are only added if reflexive_acls is set to False
    def _reverse_rule(self, r):
        """Compose and return a reverse rule for r if reflexive_acls is False

        Arguments:
        r - rule dictionary returned by the _to_acl_rule(r) method above
        swap src and dst IP and port ranges to match return traffic for r
        """
        acl_rule = {}
        # 1 == Permit rule and 0 == deny rule
        acl_rule['is_permit'] = r['is_permit']
        acl_rule['is_ipv6'] = r['is_ipv6']
        acl_rule['proto'] = r['proto']
        # All TCP/UDP IPv4 and IPv6 traffic
        if r['proto'] in [6, 17, 0]:
            if r.get('dst_ip_addr'):  # r is an egress Rule
                acl_rule['src_ip_addr'] = r['dst_ip_addr']
                acl_rule['src_ip_prefix_len'] = r['dst_ip_prefix_len']
            elif r.get('src_ip_addr'):  # r is an ingress Rule
                acl_rule['dst_ip_addr'] = r['src_ip_addr']
                acl_rule['dst_ip_prefix_len'] = r['src_ip_prefix_len']
            else:
                LOG.error("Invalid rule %s to be reversed" % r)
                return {}
            # Swap port range values
            acl_rule['srcport_or_icmptype_first'] = r[
                'dstport_or_icmpcode_first']
            acl_rule['srcport_or_icmptype_last'] = r[
                'dstport_or_icmpcode_last']
            acl_rule['dstport_or_icmpcode_first'] = r[
                'srcport_or_icmptype_first']
            acl_rule['dstport_or_icmpcode_last'] = r[
                'srcport_or_icmptype_last']
        return acl_rule

    def acl_add_replace_on_host(self, secgroup):
        """Adds/Replaces the secgroup ACL on host.

        Arguments:
        secgroup - SecurityGroup NamedTuple object
        namedtuple('SecurityGroup', ['id', 'ingress_rules', 'egress_rules'])
        """
        # Default action == ADD if the acl indexes are set to ~0
        # VPP ACL indexes correspond to ingress and egress security
        # group rules
        in_acl_idx, out_acl_idx = 0xffffffff, 0xffffffff
        if secgroup.id in secgroups:
            LOG.debug("secgroup_watcher:updating vpp acls for "
                      "security group %s" % secgroup.id)
            in_acl_idx, out_acl_idx = secgroups[secgroup.id]
            LOG.debug("secgroup_watcher:updating vpp input acl idx: %s and "
                      "output acl idx %s" % (in_acl_idx, out_acl_idx))
        else:
            LOG.debug("secgroup_watcher: adding new input and output "
                      "vpp acls for secgroup %s" % secgroup.id)
        in_acl_rules, out_acl_rules = (
            [self._to_acl_rule(r, 0) for r in secgroup.ingress_rules],
            [self._to_acl_rule(r, 1) for r in secgroup.egress_rules])
        # If not reflexive_acls create return rules for ingress and egress
        # IPv4/IPv6 tcp/udp traffic
        # Exclude ICMP
        if not reflexive_acls:
            LOG.debug("secgroup_watcher: vpp reflexive acls are disabled "
                      "vpp-agent is adding return rules")
            in_acl_return_rules, out_acl_return_rules = (
                [self._reverse_rule(r) for r in in_acl_rules
                    if r['proto'] in [6, 17, 0]],
                [self._reverse_rule(r) for r in out_acl_rules
                    if r['proto'] in [6, 17, 0]]
                )
            in_acl_rules = in_acl_rules + out_acl_return_rules
            out_acl_rules = out_acl_rules + in_acl_return_rules
        else:
            LOG.debug("secgroup_watcher: vpp reflexive_acls are enabled")
        LOG.debug("secgroup_watcher:ingress ACL rules %s for secgroup %s"
                  % (in_acl_rules, secgroup.id))
        LOG.debug("secgroup_watcher:egress ACL rules %s for secgroup %s"
                  % (out_acl_rules, secgroup.id))
        # A tag of secgroup_id:0 denotes ingress acl
        in_acl_idx = self.vpp.acl_add_replace(acl_index=in_acl_idx,
                                              tag="%s:%s" % (secgroup.id, 0),
                                              rules=in_acl_rules,
                                              count=len(in_acl_rules))
        # A tag of secgroup_id:1 denotes egress acl
        out_acl_idx = self.vpp.acl_add_replace(acl_index=out_acl_idx,
                                               tag="%s:%s" % (secgroup.id, 1),
                                               rules=out_acl_rules,
                                               count=len(out_acl_rules))
        LOG.debug("secgroup_watcher: in_acl_index:%s out_acl_index:%s "
                  "for secgroup:%s" % (in_acl_idx, out_acl_idx, secgroup.id))
        secgroups[secgroup.id] = VppAcl(in_acl_idx, out_acl_idx)
        LOG.debug("secgroup_watcher: current secgroup mapping: %s"
                  % secgroups)

    def acl_delete_on_host(self, secgroup):
        """Deletes the ingress and egress VPP ACLs on host for secgroup

        Arguments:
        secgroup - OpenStack security group ID
        """
        try:
            for acl_idx in secgroups[secgroup]:
                LOG.debug("secgroup_watcher: deleting VPP ACL %s for "
                          "secgroup %s" % (acl_idx, secgroup))
                self.vpp.acl_delete(acl_index=acl_idx)
            del secgroups[secgroup]
            LOG.debug("secgroup_watcher: current secgroup mapping: %s"
                      % secgroups)
        except KeyError:
            LOG.error("secgroup_watcher: received request to delete "
                      "an unknown security group %s" % secgroup)
        except Exception as e:
            LOG.error("Exception while deleting ACL %s" % e)

    def get_secgroup_acl_map(self):
        """Read VPP ACL tag data, construct and return an acl_map

        acl_map: {'secgroup_id:direction' : acl_idx}
        """
        acl_map = {}
        try:
            for acl in self.vpp.get_acls():
                # only the first 38 chars of the tag are of interest to us
                # if spoofing-acl only the first 6 chars of the tags are
                # of interest
                try:
                    if acl.tag[:5] in 'FFFF:':
                        acl_map[acl.tag[:6]] = acl.acl_index
                    else:
                        acl_map[acl.tag[:38]] = acl.acl_index
                except (KeyError, AttributeError):
                    # Not all ACLs have tags, but ACLs we own will have them
                    # Ignore any system-configured ACLs
                    pass

            LOG.debug("secgroup_watcher: created acl_map %s from "
                      "vpp acl tags" % acl_map)
        except Exception as e:
            LOG.error("Exception getting acl_map from vpp acl tags %s" % e)
            raise
        return acl_map

    def set_acls_on_vpp_port(self, vpp_acls, sw_if_index):
        """Build a vector of VPP ACLs and set it on the port

        Arguments -
        vpp_acls - a list of VppAcl(in_idx, out_idx) namedtuples to be set
                   on the interface. An empty list '[]' deletes all acls
                   from the interface
        """
        # Initialize lists with anti-spoofing vpp acl indices
        spoof_acl = self.spoof_filter_on_host()
        LOG.debug("secgroup_watcher: spoof_acl indices [in, out] on host %s"
                  % [spoof_acl.in_idx, spoof_acl.out_idx])
        # input acl on vpp filters egress traffic from vm and viceversa
        input_acls = [spoof_acl.out_idx]
        output_acls = [spoof_acl.in_idx]
        if vpp_acls:
            LOG.debug("secgroup_watcher: building an acl vector from acl list"
                      "%s to set on VPP sw_if_index %s"
                      % (vpp_acls, sw_if_index))
            for acl in vpp_acls:
                input_acls.append(acl.out_idx)  # in on vpp == out on vm
                output_acls.append(acl.in_idx)  # out on vpp == in on vm
        else:
            LOG.debug("secgroup_watcher: setting only spoof-filter acl %s"
                      "on vpp interface %s due to empty vpp_acls"
                      % (spoof_acl, sw_if_index))
        # Build the vpp ACL vector
        acls = input_acls + output_acls
        # (najoy) At this point we just keep a mapping of acl vectors
        # associated with a port and do not check for any repeat application.
        LOG.debug("secgroup_watcher: Setting VPP acl vector %s with "
                  "n_input %s on sw_if_index %s"
                  % (acls, len(input_acls), sw_if_index))
        status = self.vpp.set_acl_list_on_interface(sw_if_index=sw_if_index,
                                                    count=len(acls),
                                                    n_input=len(input_acls),
                                                    acls=acls)
        if status == 0:
            LOG.debug("secgroup_watcher: Successfully set VPP acl vector %s "
                      "with n_input %s on sw_if_index %s"
                      % (acls, len(input_acls), sw_if_index))
            self.port_vpp_acls[sw_if_index]['l34'] = acls
            LOG.debug("secgroup_watcher: Current port acl_vector mappings %s"
                      % str(self.port_vpp_acls))
        else:
            status = 1  # Set failure status code == 1
            LOG.error("secgroup_watcher: Failed to set VPP acl vector %s "
                      "with n_input %s on sw_if_index %s"
                      % (acls, len(input_acls), sw_if_index))
        return status

    def set_mac_ip_acl_on_vpp_port(self, mac_ips, sw_if_index):
        """Set the mac-filter on VPP port

        Arguments:
        mac_ips - A list of tuples of (mac_address, ip_address)
        sw_if_index - Software index ID of the VPP port
        """

        def _pack_mac(mac_address):
            """Pack a mac_address into binary."""
            return binascii.unhexlify(mac_address.replace(':', ''))

        def _get_ip_version(ip):
            """Return the IP Version 4 or 6"""
            ip_addr = ip_address(ip)
            return ip_addr.version

        src_mac_mask = _pack_mac('FF:FF:FF:FF:FF:FF')
        mac_ip_rules = []
        for mac, ip in mac_ips:
            ip_version = _get_ip_version(ip)
            is_ipv6 = 1 if ip_version == 6 else 0
            ip_prefix = 32 if ip_version == 4 else 128
            mac_ip_rules.append(
                {'is_permit': 1,
                 'is_ipv6': is_ipv6,
                 'src_mac': _pack_mac(mac),
                 'src_mac_mask': src_mac_mask,
                 'src_ip_addr': self._pack_address(ip),
                 'src_ip_prefix_len': ip_prefix})
        # get the current mac_ip_acl on the port if_any
        port_mac_ip_acl = None
        try:
            port_mac_ip_acl = self.port_vpp_acls[sw_if_index]['l23']
        except KeyError:
            pass  # There may not be an ACL on the interface
        LOG.debug("secgroup_watcher: Adding macip acl with rules %s"
                  % mac_ip_rules)
        acl_index = self.vpp.macip_acl_add(rules=mac_ip_rules,
                                           count=len(mac_ip_rules))
        LOG.debug("secgroup_watcher: Setting mac_ip_acl index %s "
                  "on interface %s" % (acl_index, sw_if_index))
        status = self.vpp.set_macip_acl_on_interface(sw_if_index=sw_if_index,
                                                     acl_index=acl_index,
                                                     )
        if status == 0:
            LOG.debug("secgroup_watcher: Successfully set macip acl %s on "
                      "interface %s - got status %s" % (acl_index,
                                                        sw_if_index,
                                                        status))
            if port_mac_ip_acl:  # Delete the previous macip ACL from VPP
                self.vpp.delete_macip_acl(acl_index=port_mac_ip_acl)
            self.port_vpp_acls[sw_if_index]['l23'] = acl_index
        else:
            LOG.error("secgroup_watcher: Error setting macip acl %s on "
                      "interface %s - got status %s" % (acl_index,
                                                        sw_if_index,
                                                        status))
        return status

    def spoof_filter_on_host(self):
        """Adds a spoof filter ACL on host if not already present.

        A spoof filter is identified by the ID: "FFFF" in secgroups mapping
        If not present create the filter on host
        Return: VppAcl(in_idx, out_idx)
        """
        # Check if we have an existing spoof filter deployed on vpp
        spoof_acl = secgroups.get('FFFF')
        if not spoof_acl:  # Deploy new spoof_filter ingress+egress vpp acls
            spoof_filter_rules = self.get_spoof_filter_rules()
            LOG.debug("secgroup_watcher: adding a new spoof filter acl "
                      "with rules %s" % spoof_filter_rules)
            # A tag of FFFF:0 denotes ingress spoof acl
            in_acl_idx = self.vpp.acl_add_replace(
                acl_index=0xffffffff,
                tag="FFFF:0",
                rules=spoof_filter_rules['ingress'],
                count=len(spoof_filter_rules['ingress'])
                )
            # A tag of FFFF:1 denotes egress spoof acl
            out_acl_idx = self.vpp.acl_add_replace(
                acl_index=0xffffffff,
                tag="FFFF:1",
                rules=spoof_filter_rules['egress'],
                count=len(spoof_filter_rules['egress'])
                )
            LOG.debug("secgroup_watcher: in_acl_index:%s out_acl_index:%s "
                      "for spoof filter" % (in_acl_idx, out_acl_idx))
            spoof_acl = VppAcl(in_acl_idx, out_acl_idx)
            if (spoof_acl.in_idx != 0xFFFFFFFF
                    and spoof_acl.out_idx != 0xFFFFFFFF):
                LOG.debug("secgroup_watcher: adding spoof_acl %s to secgroup "
                          "mapping %s" % (str(spoof_acl), secgroups))
                secgroups['FFFF'] = spoof_acl
                LOG.debug("secgroup_watcher: current secgroup mapping: %s"
                          % secgroups)
            else:
                LOG.error("secgroup_watcher: could not add a valid ingress/"
                          "egress spoof acl in VPP. We got an invalid acl "
                          "index %s from vpp" % str(spoof_acl))
        else:
            LOG.debug("secgroup_watcher: found an existing spoof acl "
                      "in vpp with indices [in_idx, out_idx] = %s"
                      % [spoof_acl.in_idx, spoof_acl.out_idx])
        return spoof_acl

    def _pack_address(self, ip_addr):
        """Pack an IPv4 or IPv6 ip_addr into binary."""
        return ip_address(unicode(ip_addr)).packed

    def get_spoof_filter_rules(self):
        """Build and return a list of anti-spoofing rules.

        Returns a dict with two keys named: ingress_rules and egress_rules
        ingress_rules = a list of ingress rules
        egress_rules = a list of egress rules
        """
        def _compose_rule(is_permit,
                          is_ipv6,
                          src_ip_addr,
                          src_ip_prefix_len,
                          dst_ip_addr,
                          dst_ip_prefix_len,
                          proto,
                          srcport_or_icmptype_first,
                          srcport_or_icmptype_last,
                          dstport_or_icmpcode_first,
                          dstport_or_icmpcode_last):
            # Set is_permit = 2  if reflexive_acls and tcp/udp/ip traffic
            if is_permit == 1 and reflexive_acls and proto in [6, 17, 0]:
                is_permit = 2
            return {
                'is_permit': is_permit,
                'is_ipv6': is_ipv6,
                'src_ip_addr': self._pack_address(src_ip_addr),
                'src_ip_prefix_len': src_ip_prefix_len,
                'dst_ip_addr': self._pack_address(dst_ip_addr),
                'dst_ip_prefix_len': dst_ip_prefix_len,
                'proto': proto,
                'srcport_or_icmptype_first': srcport_or_icmptype_first,
                'srcport_or_icmptype_last': srcport_or_icmptype_last,
                'dstport_or_icmpcode_first': dstport_or_icmpcode_first,
                'dstport_or_icmpcode_last': dstport_or_icmpcode_last
                }
        # Ingress filter rules to allow DHCP and ICMPv6 into VM
        # Allow incoming DHCP offer packets from dhcp servers
        #  UDP src_port 67 (ipv4 dhcp server) and dst_port 68 (dhclient)
        #  UDP src_port 547 (ipv6 dhserver) and dst_port 546 (ipv6 dclient)
        ingress_rules = [
            _compose_rule(1, 0, '0.0.0.0', 0, '0.0.0.0', 0,
                          17, 67, 67, 68, 68),
            _compose_rule(1, 1, '::', 0, '::', 0,
                          17, 547, 547, 546, 546),
            ]
        # Allow Icmpv6 Multicast listener Query, Report, Done (130,131,132)
        # neighbor soliciation (135) and neighbor advertisement (136) and
        # MLD2_REPORT (143) and ICMP_RA into the Instance
        ICMP_RA = n_const.ICMPV6_TYPE_RA
        for ICMP_TYPE in [130, 131, 132, 135, 136, 143, ICMP_RA]:
            ingress_rules.append(
                _compose_rule(1, 1, '::', 0, '::', 0,
                              58, ICMP_TYPE, ICMP_TYPE, 0, 255)
                )
        # Egress spoof_filter rules from VM
        # Permit DHCP client packets (discovery + request)
        #   UDP src_port 68 (ipv4 client) and dst_port 67 (ipv4 dhcp server)
        #   UDP src_port 546 (ipv6 client) and dst_port 547 (ipv6 dhcp server)
        # Drop DHCP Offer packets originating from VM
        #  src_port 67 and dst_port 68
        #  src_port 547 and dst_port 546
        # Drop icmpv6 Router Advertisements from VMs.
        #  Allow other outgoing icmpv6 packets
        egress_rules = [
            _compose_rule(1, 0, '0.0.0.0', 0, '0.0.0.0', 0,
                          17, 68, 68, 67, 67),
            _compose_rule(1, 1, '::', 0, '::', 0,
                          17, 546, 546, 547, 547),
            _compose_rule(0, 0, '0.0.0.0', 0, '0.0.0.0', 0,
                          17, 67, 67, 68, 68),
            _compose_rule(0, 1, '::', 0, '::', 0,
                          17, 547, 547, 546, 546),
            _compose_rule(0, 1, '::', 0, '::', 0,
                          58, ICMP_RA, ICMP_RA, 0, 255),
            _compose_rule(1, 1, '::', 0, '::', 0,
                          58, 0, 255, 0, 255),
            ]

        return {'ingress': ingress_rules,
                'egress': egress_rules}

    def get_macip_acl_dump(self):
        """Get a dump of macip ACLs on the node"""
        return self.vpp.get_macip_acl_dump()

######################################################################

LEADIN = '/networking-vpp'  # TODO(ijw): make configurable?


class EtcdListener(object):
    def __init__(self, host, etcd_client, vppf, physnets):
        self.host = host
        self.etcd_client = etcd_client
        self.vppf = vppf
        self.physnets = physnets
        self.etcd_helper = nwvpp_utils.EtcdHelper(self.etcd_client)
        # We need certain directories to exist
        self.mkdir(LEADIN + '/state/%s/ports' % self.host)
        self.mkdir(LEADIN + '/nodes/%s/ports' % self.host)
        self.pool = eventlet.GreenPool()
        self.secgroup_enabled = cfg.CONF.SECURITYGROUP.enable_security_group

        # key: if index in VPP; value: (ID, prop-dict) tuple
        self.iface_state = {}

        self.vppf.vhost_ready_callback = self._vhost_ready

    def mkdir(self, path):
        try:
            self.etcd_client.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass

    def repop_interfaces(self):
        pass

    # The vppf bits

    def unbind(self, id):
        self.vppf.unbind_interface_on_host(id)

    def bind(self, id, binding_type, mac_address, physnet, network_type,
             segmentation_id):
        # args['binding_type'] in ('vhostuser', 'plugtap'):
        props = self.vppf.bind_interface_on_host(binding_type,
                                                 id,
                                                 mac_address,
                                                 physnet,
                                                 network_type,
                                                 segmentation_id)

        iface_idx = props['iface_idx']
        self.iface_state[iface_idx] = (id, props)
        if (binding_type != 'vhostuser' or
           self.vppf.vhostuser_linked_up(iface_idx)):
            # Handle the case were the interface has already been
            # notified as up, as we need both the up-notification
            # and bind information ito be ready before we tell Nova
            # For tap devices, the interface is now ready for a VM
            self._mark_up(iface_idx)

        return props

    def _vhost_ready(self, sw_if_index):
        if sw_if_index in self.iface_state:
            # This index is linked up, and it's one of ours
            self._mark_up(sw_if_index)

    def _mark_up(self, sw_if_index):
        """Flag to Nova that an interface is connected.

        Nova watches a key's existence before sending out
        bind events.  We set the key, and use the value
        to store debugging information.
        """
        LOG.debug('marking index %s as ready', str(sw_if_index))
        (port, props) = self.iface_state[sw_if_index]
        self.etcd_client.write(self.state_key_space + '/%s' % port,
                               json.dumps(props))

    def acl_add_replace(self, secgroup, data):
        """Add or replace a VPP ACL.

        Arguments:
        secgroup - OpenStack SecurityGroup ID
        data - SecurityGroup data from etcd
        """
        LOG.debug("secgroup_watcher: acl_add_replace secgroup %s data %s"
                  % (secgroup, data))

        def _secgroup_rule(r):
            ip_addr = unicode(r['remote_ip_addr'])
            # VPP API requires the IP addresses to be represented in binary
            return SecurityGroupRule(r['is_ipv6'],
                                     ip_address(ip_addr).packed,
                                     r['ip_prefix_len'], r['protocol'],
                                     r['port_min'], r['port_max'])
        ingress_rules, egress_rules = (
            [_secgroup_rule(r) for r in data['ingress_rules']],
            [_secgroup_rule(r) for r in data['egress_rules']]
            )
        self.vppf.acl_add_replace_on_host(SecurityGroup(secgroup,
                                                        ingress_rules,
                                                        egress_rules))

    def acl_delete(self, secgroup):
        """Delete ACL on host.

        Arguments:
        secgroup - OpenStack SecurityGroup ID
        """
        LOG.debug("secgroup_watcher: deleting secgroup %s" % secgroup)
        self.vppf.acl_delete_on_host(secgroup)

    def populate_secgroup_acl_mappings(self):
        """From vpp acl dump, populate the secgroups to VppACL mapping.

        Get a dump of existing vpp acls
        Read tag info
        Tag format: secgroup_id:0 for in_idx && secgroup_id:1 for out_idx
        populate secgroups data structure
        secgroups = {secgroup_id : VppAcl(in_idx, out_idx)}
        """
        LOG.debug("secgroup_watcher: Populating secgroup to VPP ACL map..")
        # Clear existing secgroups to ACL map for sanity
        LOG.debug("secgroup_watcher: Clearing existing secgroups "
                  "to vpp-acl mappings")
        global secgroups
        secgroups = {}
        # acl_map: {'secgroup_id:direction' : acl_idx}
        # direction == 0 for ingress and direction == 1 for egress
        acl_map = self.vppf.get_secgroup_acl_map()
        try:
            for item in acl_map:
                secgroup_id, direction = item.split(":")
                acl_idx = acl_map[item]
                ingress = True if int(direction) == 0 else False
                vpp_acl = secgroups.get(secgroup_id)
                if not vpp_acl:  # create a new secgroup to acl mapping
                    if ingress:  # create partial ingress acl mapping
                        secgroups[secgroup_id] = VppAcl(acl_idx, 0xffffffff)
                    else:  # create partial egress ACL mapping
                        secgroups[secgroup_id] = VppAcl(0xffffffff, acl_idx)
                else:  # secgroup in map with one acl_idx, update the other idx
                    if ingress:  # replace ingress ACL idx
                        secgroups[secgroup_id] = vpp_acl._replace(
                            in_idx=acl_idx)
                    else:  # replace egress ACL idx
                        secgroups[secgroup_id] = vpp_acl._replace(
                            out_idx=acl_idx)
            LOG.debug("secgroup_watcher: secgroup to VPP ACL mapping %s "
                      "constructed by reading "
                      "acl tags and building an acl_map %s"
                      % (secgroups, acl_map))
            if not secgroups:
                LOG.debug("secgroup_watcher: We have an empty secgroups "
                          "to acl mapping {}. Possible reason: vpp "
                          "may have been restarted on host.")
        except ValueError:
            pass  # Any tag with incorrect format can generate this - ignore

    def spoof_filter_on_host(self):
        """Deploy anti-spoofing ingress and egress ACLs on VPP.

        Tag ingress spoof acl on VPP with ID: FFFF:0
        Tag egress spoof acl on VPP with ID: FFFF:1
        Add Spoof ACL mapping with Key: "FFFF"
                                   Val: VppAcl(in_idx, out_idx)
        to secgroups mapping
        """
        self.vppf.spoof_filter_on_host()

    def set_acls_on_port(self, secgroup_ids, sw_if_index):
        """Compute a vector of input/output ACLs and set it on the VPP port.

        Arguments:
        secgroup_ids - OpenStack Security Group IDs
        sw_if_index - VPP software interface index on which the ACLs will
        be set

        This method is spawned as a greenthread. It looks up the global
        secgroups to acl mapping to figure out the ACL indexes associated
        with the secgroup. If the secgroup cannot be found or if the ACL
        index is invalid i.e. 0xffffffff it will wait for a period of time
        for this data to become available. This happens mostly in agent
        restart situations when the secgroups mapping is still being
        populated by the secgroup watcher thread. It then composes the
        acl vector and programs the port using vppf.
        """
        class InvalidACLError(Exception):
            """Raised when a VPP ACL is invalid."""
            pass

        class ACLNotFoundError(Exception):
            """Raised when a VPP ACL is not found for a security group."""
            pass

        # A list of VppAcl namedtuples to be set on the port
        vpp_acls = []
        for secgroup_id in secgroup_ids:
            try:
                acl = secgroups[secgroup_id]
                # If any one or both indices are invalid wait for a valid acl
                if (acl.in_idx == 0xFFFFFFFF or acl.out_idx == 0xFFFFFFFF):
                    LOG.debug("port_watcher: Waiting for a valid vpp acl "
                              "corresponding to secgroup %s" % secgroup_id)
                    raise InvalidACLError
                else:
                    vpp_acls.append(acl)
            except (KeyError, InvalidACLError):
                # Here either the secgroup_id is not present or acl is invalid
                acl = None
                # Wait for the mapping in secgroups to populate
                # This is required because it may take sometime for the
                # secgroup-worker thread to build and populate the
                # security-groups to vpp-acl map
                timeout = eventlet.timeout.Timeout(60, False)
                found = False
                with timeout:  # Do not raise eventlet Exc.
                    while True and not found:
                        acl = secgroups.get(secgroup_id)
                        # cancel timeout if acl and both its indices are valid
                        if (acl and acl.in_idx != 0xFFFFFFFF
                                and acl.out_idx != 0xFFFFFFFF):
                                LOG.debug("port_watcher: Found a valid vpp "
                                          "acl %s for "
                                          "secgroup %s" % (acl, secgroup_id))
                                timeout.cancel()
                                found = True  # Req. for non-greenthread runs
                        else:  # sleep and wait for the ACL
                            LOG.debug("port_watcher: Waiting 2 secs to "
                                      "for the secgroup: %s to VppAcl "
                                      "mapping to populate" % secgroup_id)
                            time.sleep(2)
                # Check for valid ACL and indices after timeout, append to list
                if (acl and acl.in_idx != 0xFFFFFFFF
                        and acl.out_idx != 0xFFFFFFFF):
                        LOG.debug("port_watcher: Found VppAcl %s for "
                                  "secgroup %s" % (acl, secgroup_id))
                        vpp_acls.append(acl)
                else:
                    LOG.error("port_watcher: Unable to locate a valid VPP ACL"
                              "for secgroup %s in secgroups mapping %s after "
                              "waiting several seconds for the mapping to "
                              "populate" % (secgroup_id, secgroups))
                    raise ACLNotFoundError("Could not find an ACL for "
                                           "Secgroup %s" % secgroup_id)
            except (ACLNotFoundError, Exception) as e:
                LOG.error("port_watcher: ran into an exception while "
                          "setting secgroup_ids %s on vpp port %s "
                          "- details %s" % (secgroup_ids, sw_if_index, e))
        LOG.debug("port_watcher: setting vpp acls %s on port sw_if_index %s "
                  "for secgroups %s" % (vpp_acls, sw_if_index, secgroup_ids))
        return self.vppf.set_acls_on_vpp_port(vpp_acls, sw_if_index)

    def set_mac_ip_acl_on_port(self, mac_address, fixed_ips,
                               allowed_address_pairs, sw_if_index):
        """Set L2/L3 ACLs on port.

        Arguments:-
        mac_address - The mac_address assigned to the port
        fixed_ips - A list of dictionaries containing the fixed_ips
                    assigned to the port identified by the key - 'ip_address'
        allowed_address_pairs - A list of allowed address pair attributes
                    - Each address pair is a dict with
                      keys: ip_address (required)
                            mac_address (optional)
        sw_if_index - VPP vhostuser  if_idx
        """
        # Allowed mac_ip list to permit for DHCP request from 0.0.0.0
        allowed_mac_ips = [(mac_address, u'0.0.0.0')]
        # A list of tuples of MAC Addrs. and their corresponding IP Addrs.
        fixed_ip_addrs = [ip['ip_address'] for ip in fixed_ips]
        mac_ips = [(mac_address, ip_address) for ip_address
                   in fixed_ip_addrs]
        # use the port-mac if a mac_address is not present in the allowed
        # address pair
        addr_pairs = [(p.get('mac_address', mac_address), p['ip_address'])
                      for p in allowed_address_pairs]
        mac_ips = allowed_mac_ips + mac_ips + addr_pairs
        LOG.debug("port_watcher: setting mac-ip allowed address pairs %s "
                  "on port %s" % (mac_ips, sw_if_index))
        return self.vppf.set_mac_ip_acl_on_vpp_port(mac_ips, sw_if_index)

    def load_macip_acl_mapping(self):
        """Load the sw_if_index to mac_ip_acl index mappings on vpp.

        Populates self.vppf.port_vpp_acls :
                  {sw_if_index -> {'l23' : <macip_acl_index>}}
        """
        try:
            macip_acls = self.vppf.get_macip_acl_dump().acls
            # The acl position is the sw_if_index
            for sw_if_index, acl_index in enumerate(macip_acls):
                if acl_index != 4294967295:  # Exclude invalid acl index
                    self.vppf.port_vpp_acls[sw_if_index]['l23'] = acl_index
            LOG.debug('port_watcher: Existing mac-ip acl map %s'
                      % self.vppf.port_vpp_acls)
        except ValueError:
            pass  # vpp_papi throws this error when no ACLs exist
        except AttributeError:
            pass   # cannot reference acl attribute - pass and exit

    AGENT_HEARTBEAT = 60  # seconds

    def process_ops(self):
        # TODO(ijw): needs to remember its last tick on reboot, or
        # reconfigure from start (which means that VPP needs it
        # storing, so it's lost on reboot of VPP)
        physnets = self.physnets.keys()
        for f in physnets:
            self.etcd_client.write(LEADIN + '/state/%s/physnets/%s'
                                   % (self.host, f), 1)

        self.port_key_space = LEADIN + "/nodes/%s/ports" % self.host
        self.state_key_space = LEADIN + "/state/%s/ports" % self.host
        self.secgroup_key_space = LEADIN + "/global/secgroups"
        # load sw_if_index to macip acl index mappings
        self.load_macip_acl_mapping()

        self.etcd_helper.clear_state(self.state_key_space)

        class PortWatcher(EtcdWatcher):

            def do_tick(self):
                # The key that indicates to people that we're alive
                # (not that they care)
                self.etcd_client.write(LEADIN + '/state/%s/alive' %
                                       self.data.host,
                                       1, ttl=3 * self.heartbeat)

            def resync(self):
                # TODO(ijw): Need to do something here to prompt
                # appropriate unbind/rebind behaviour
                pass

            def do_work(self, action, key, value):
                # Matches a port key, gets host and uuid
                m = re.match(self.data.port_key_space + '/([^/]+)$', key)

                if m:
                    port = m.group(1)

                    if action == 'delete':
                        # Removing key == desire to unbind
                        self.data.unbind(port)
                        LOG.debug("port_watcher: known secgroup to acl "
                                  "mappings %s" % secgroups)
                        try:
                            self.etcd_client.delete(
                                self.data.state_key_space + '/%s'
                                % port)
                        except etcd.EtcdKeyNotFound:
                            # Gone is fine; if we didn't delete it
                            # it's no problem
                            pass
                    else:
                        # Create or update == bind
                        data = json.loads(value)
                        props = self.data.bind(port,
                                               data['binding_type'],
                                               data['mac_address'],
                                               data['physnet'],
                                               data['network_type'],
                                               data['segmentation_id'])

                        # If security-groups is enabled, set L3/L2 ACLs
                        # TODO(najoy): Set ACLs on the interface before
                        # it is marked as up and a notification sent to nova
                        if (self.data.secgroup_enabled
                                and data['binding_type'] == 'vhostuser'):
                            LOG.debug("port_watcher: known secgroup to acl "
                                      "mappings %s" % secgroups)
                            security_groups = data.get('security_groups', [])
                            LOG.debug("port_watcher:Setting secgroups %s "
                                      "on sw_if_index %s for port %s" %
                                      (security_groups,
                                       props['iface_idx'],
                                       port))
                            result = self.data.set_acls_on_port(
                                security_groups,
                                props['iface_idx'])
                            LOG.debug("port_watcher: setting secgroups "
                                      "%s on sw_if_index %s for port %s "
                                      "returned status code %s" %
                                      (security_groups,
                                       props['iface_idx'],
                                       port,
                                       result))
                            # Set Allowed address pairs and mac-spoof filter
                            aa_pairs = data.get('allowed_address_pairs', [])
                            LOG.debug("port_watcher: Setting allowed "
                                      "address pairs %s on port %s "
                                      "sw_if_index %s" %
                                      (aa_pairs,
                                       port,
                                       props['iface_idx']))
                            result = self.data.set_mac_ip_acl_on_port(
                                data['mac_address'],
                                data.get('fixed_ips'),
                                aa_pairs,
                                props['iface_idx'])
                            LOG.debug("port_watcher: setting allowed-addr-"
                                      "pairs %s on sw_if_index %s for port "
                                      "%s returned status code %s" %
                                      (aa_pairs,
                                       props['iface_idx'],
                                       port,
                                       result))

                else:
                    LOG.warning('Unexpected key change in etcd port feedback, '
                                'key %s', key)

        LOG.debug("Spawning port_watcher")
        self.pool.spawn(PortWatcher(self.etcd_client, 'port_watcher',
                                    self.port_key_space,
                                    heartbeat=self.AGENT_HEARTBEAT,
                                    data=self).watch_forever)

        class SecGroupWatcher(EtcdWatcher):

            def do_tick(self):
                pass

            def resync(self):
                pass

            def do_work(self, action, key, value):
                # Matches a security group key and does work
                LOG.debug("secgroup_watcher: doing work for %s %s %s" %
                          (action, key, value))
                # Matches a secgroup key and gets its ID and data
                m = re.match(self.data.secgroup_key_space + '/([^/]+)$', key)
                if m:
                    secgroup = m.group(1)
                    if action == 'delete':
                        LOG.debug("secgroup_watcher: deleting secgroup %s"
                                  % secgroup)
                        self.data.acl_delete(secgroup)
                        LOG.debug("secgroup watcher: known secgroup to acl "
                                  "mappings %s" % secgroups)
                        try:
                            self.etcd_client.delete(
                                self.data.secgroup_key_space + '/%s'
                                % secgroup)
                        except etcd.EtcdKeyNotFound:
                            pass
                    else:
                        # create or update a secgroup == add_replace vpp acl
                        data = json.loads(value)
                        LOG.debug("secgroup_watcher: add_replace secgroup %s"
                                  % secgroup)
                        self.data.acl_add_replace(secgroup, data)
                        LOG.debug("secgroup_watcher: known secgroup to acl "
                                  "mappings %s" % secgroups)
                else:
                    LOG.warning('secgroup_watcher: Unexpected change in '
                                'etcd secgroup feedback for key %s' % key)

        if self.secgroup_enabled:
            LOG.debug("loading VppAcl map from acl tags for "
                      "performing secgroup_watcher lookups")
            self.populate_secgroup_acl_mappings()
            LOG.debug("Adding ingress/egress spoof filters "
                      "on host for secgroup_watcher spoof blocking")
            self.spoof_filter_on_host()
            LOG.debug("Spawning secgroup_watcher..")
            self.pool.spawn(SecGroupWatcher(self.etcd_client,
                                            'secgroup_watcher',
                                            self.secgroup_key_space,
                                            heartbeat=self.AGENT_HEARTBEAT,
                                            data=self).watch_forever)
        self.pool.waitall()


class VPPRestart(object):
    def __init__(self):
        self.timeout = 10  # VPP connect timeout in seconds
        LOG.debug("Agent is restarting VPP")
        utils.execute(['service', 'vpp', 'restart'], run_as_root=True)

    def wait(self):
        time.sleep(self.timeout)  # TODO(najoy): check if vpp is actually up


def main():
    cfg.CONF(sys.argv[1:])
    logging.setup(cfg.CONF, 'vpp_agent')

    # If the user and/or group are specified in config file, we will use
    # them as configured; otherwise we try to use defaults depending on
    # distribution. Currently only supporting ubuntu and redhat.
    cfg.CONF.register_opts(config_opts.vpp_opts, "ml2_vpp")
    if cfg.CONF.ml2_vpp.enable_vpp_restart:
        LOG.debug('Restarting VPP..')
        VPPRestart().wait()

    if not cfg.CONF.ml2_vpp.physnets:
        LOG.error("Missing physnets config. Exiting...")
        sys.exit(1)

    physnet_list = cfg.CONF.ml2_vpp.physnets.replace(' ', '').split(',')
    physnets = {}
    for f in physnet_list:
        if f:
            try:
                (k, v) = f.split(':')
                physnets[k] = v
            except Exception:
                LOG.error("Could not parse physnet to interface mapping "
                          "check the format in the config file: "
                          "physnets = physnet1:<interface1>, "
                          "physnet2:<interface>"
                          )
                sys.exit(1)
    vppf = VPPForwarder(physnets,
                        mac_age=cfg.CONF.ml2_vpp.mac_age,
                        vxlan_src_addr=cfg.CONF.ml2_vpp.vxlan_src_addr,
                        vxlan_bcast_addr=cfg.CONF.ml2_vpp.vxlan_bcast_addr,
                        vxlan_vrf=cfg.CONF.ml2_vpp.vxlan_vrf)

    LOG.debug("Using etcd host:%s port:%s user:%s password:***",
              cfg.CONF.ml2_vpp.etcd_host,
              cfg.CONF.ml2_vpp.etcd_port,
              cfg.CONF.ml2_vpp.etcd_user)

    host = nwvpp_utils.parse_host_config(cfg.CONF.ml2_vpp.etcd_host,
                                         cfg.CONF.ml2_vpp.etcd_port)

    etcd_client = etcd.Client(host=host,
                              username=cfg.CONF.ml2_vpp.etcd_user,
                              password=cfg.CONF.ml2_vpp.etcd_pass,
                              allow_reconnect=True)

    ops = EtcdListener(cfg.CONF.host, etcd_client, vppf, physnets)

    ops.process_ops()

if __name__ == '__main__':
    main()
