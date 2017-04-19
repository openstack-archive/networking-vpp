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

# Note that it does *NOT* at this point have a persistent database, so
# restarting this process will make net-vpp forget about every port it's
# learned, which will not do your system much good (the data is in the
# global 'backends' and 'ports' objects).  This is for simplicity of
# demonstration; we have a second codebase already defined that is
# written to OpenStack endpoint principles and includes its ORM, so
# that work was not repeated here where the aim was to get the APIs
# worked out.  The two codebases will merge in the future.

# eventlet must be monkey patched early or we confuse urllib3.
import eventlet

# We actually need to co-operate with a threaded callback in VPP, so
# don't monkey patch the thread operations.
eventlet.monkey_patch(thread=False)

import binascii
import etcd
import json
import os
import re
import sys
import time
import vpp

from collections import defaultdict
from collections import namedtuple
from ipaddress import ip_address
from ipaddress import ip_network
from networking_vpp.agent import utils as nwvpp_utils
from networking_vpp import compat
from networking_vpp.compat import n_const
from networking_vpp import config_opts
from networking_vpp.etcdutils import EtcdChangeWatcher
from networking_vpp.mech_vpp import SecurityGroup
from networking_vpp.mech_vpp import SecurityGroupRule

from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import config
from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

# A model of a bi-directional VPP ACL corresponding to a secgroup
VppAcl = namedtuple('VppAcl', ['in_idx', 'out_idx'])

# TODO(najoy) Expose the below as a config option
# Enable stateful reflexive ACLs in VPP which adds automatic reverse rules
# When False, reverse rules are added by the vpp-agent and
# VPP does not maintain any session states
reflexive_acls = True

# config_opts and config are required to configure the options within it, but
# not referenced from here, so shut up tox:
assert config_opts
assert config

# Apply monkey patch if necessary
compat.monkey_patch()

######################################################################

# This mirrors functionality in Neutron so that we're creating a name
# that Neutron can find for its agents.

DEV_NAME_PREFIX = n_const.TAP_DEVICE_PREFIX

######################################################################
# TODO(ijw): should be pulled from Neutron or Nova - this naming
# scheme is common between both

TAP_UUID_LEN = 11


def get_tap_name(uuid):
    return n_const.TAP_DEVICE_PREFIX + uuid[0:TAP_UUID_LEN]


def get_bridge_name(uuid):
    return 'br-' + uuid[0:TAP_UUID_LEN]


# This is our internal name and the other end neither knows or cares about
# it, only the bridge we put it in
def get_vpptap_name(uuid):
    return 'vpp' + uuid[0:TAP_UUID_LEN]

######################################################################


def VPP_TAG(tag):
    return 'net-vpp.' + tag

# Interface tagging naming scheme :
# tap and vhost interfaces: port:<uuid>
# Uplink Connectivity: uplink:<net_type>.<seg_id>


# MAX_PHYSNET_LENGTH + the tag format must be <= the 64 bytes of a VPP tag
MAX_PHYSNET_LENGTH = 32
TAG_PHYSNET_IF_PREFIX = VPP_TAG('physnet:')
TAG_UPLINK_PREFIX = VPP_TAG('uplink:')
TAG_L2IFACE_PREFIX = VPP_TAG('port:')


def get_vhostuser_name(uuid):
    return os.path.join(cfg.CONF.ml2_vpp.vhost_user_dir, uuid)


def physnet_if_tag(physnet_name):
    return TAG_PHYSNET_IF_PREFIX + physnet_name


def decode_physnet_if_tag(tag):
    if tag is None:
        return None
    m = re.match('^' + TAG_PHYSNET_IF_PREFIX + '([^.]+)$', tag)
    return None if m is None else m.group(1)


def uplink_tag(physnet, net_type, seg_id):
    return TAG_UPLINK_PREFIX + '%s.%s.%s' % (physnet, net_type, seg_id)


def decode_uplink_tag(tag):
    """Spot an uplink interface tag.

    Return (net_type, seg_id) or None if not an uplink tag
    """
    if tag is None:
        return None  # not tagged
    m = re.match('^' + TAG_UPLINK_PREFIX + '([^.]+)\.([^.]+)\.([^.]+)$', tag)
    return None if m is None else (m.group(1), m.group(2), m.group(3))


def port_tag(port_uuid):
    return TAG_L2IFACE_PREFIX + str(port_uuid)


def decode_port_tag(tag):
    """Spot a port interface tag

    Return uuid or None if not a port interface tag.
    """
    if tag is None:
        return None  # not tagged
    m = re.match('^' + TAG_L2IFACE_PREFIX + '(' + n_const.UUID_PATTERN + ')$',
                 tag)
    return None if m is None else m.group(1)


######################################################################

# Security group tag formats used to tag ACLs in VPP for
# re-identification on restart

# When leaving VPP and entering the VM
VPP_TO_VM = 1
# When leaving the VM and entering VPP
VM_TO_VPP = 0
VPP_TO_VM_MARK = 'from-vpp'
VM_TO_VPP_MARK = 'to-vpp'


def VPP_TO_VM_TAG(tag):
    return tag + '.' + VPP_TO_VM_MARK


def VM_TO_VPP_TAG(tag):
    return tag + '.' + VM_TO_VPP_MARK


def DIRECTION_TAG(tag, is_vm_ingress):
    if is_vm_ingress:
        return VPP_TO_VM_TAG(tag)
    else:
        return VM_TO_VPP_TAG(tag)

COMMON_SPOOF_TAG = VPP_TAG('common_spoof')
COMMON_SPOOF_VPP_TO_VM_TAG = VPP_TO_VM_TAG(COMMON_SPOOF_TAG)
COMMON_SPOOF_VM_TO_VPP_TAG = VM_TO_VPP_TAG(COMMON_SPOOF_TAG)


def common_spoof_tag(is_vm_ingress):
    if is_vm_ingress:
        return COMMON_SPOOF_VPP_TO_VM_TAG
    else:
        return COMMON_SPOOF_VM_TO_VPP_TAG


def decode_common_spoof_tag(tag):
    """Work out if this tag is one of our common spoof filter tags

    """
    if COMMON_SPOOF_VPP_TO_VM_TAG == tag:
        return 1
    if COMMON_SPOOF_VM_TO_VPP_TAG == tag:
        return 0

    return None

SECGROUP_TAG = VPP_TAG('secgroup:')


def secgroup_tag(secgroup_id, is_vm_ingress):
    base_tag = SECGROUP_TAG + secgroup_id
    return DIRECTION_TAG(base_tag, is_vm_ingress)


def decode_secgroup_tag(tag):
    # Matches the formats constructed earlier
    m = re.match('^' + SECGROUP_TAG + '(' + n_const.UUID_PATTERN + ')\.(.*)$',
                 tag)
    if m:
        secgroup_id = m.group(1)
        dirmark = m.group(2)
        is_vm_ingress = dirmark == VPP_TO_VM_MARK
        return secgroup_id, is_vm_ingress

    return None, None

######################################################################
# GPE constants
# A name for a GPE locator-set, which is a set of underlay interface indexes
gpe_lset_name = 'net-vpp-gpe-lset-1'

#######################################################################


class UnsupportedInterfaceException(Exception):
    pass


class VPPForwarder(object):
    """Convert agent requirements into VPP calls

    This class has no interaction with etcd; other classes have no
    interaction with VPP.  The job of this class is to turn the
    demands of etcd's data into VPP constructs.
    """

    def __init__(self,
                 physnets,  # physnet_name: interface-name
                 mac_age,
                 tap_wait_time,
                 vpp_cmd_queue_len=None,
                 gpe_src_cidr=None,
                 vxlan_src_addr=None,
                 vxlan_bcast_addr=None,
                 vxlan_vrf=None,
                 gpe_locators=None):
        self.vpp = vpp.VPPInterface(LOG, vpp_cmd_queue_len)

        self.physnets = physnets

        self.mac_age = mac_age

        # a Mapping of security groups to VPP ACLs
        self.secgroups = {}  # secgroup_uuid: VppAcl(ingress_idx, egress_idx)

        # This is the address we'll use if we plan on broadcasting
        # vxlan packets
        self.vxlan_bcast_addr = vxlan_bcast_addr
        self.vxlan_src_addr = vxlan_src_addr
        # GPE underlay IP address/mask
        self.gpe_src_cidr = gpe_src_cidr
        self.vxlan_vrf = vxlan_vrf
        # Name of the GPE physnet uplink and its address
        self.gpe_locators = gpe_locators
        self.gpe_underlay_addr = None

        self.networks = {}      # (physnet, type, ID): datastruct
        self.interfaces = {}    # uuid: if idx
        # mac_ip acls do not support atomic replacement.
        # Here we create a mapping of sw_if_index to VPP ACL indices
        # so we can easily lookup the ACLs associated with the interface idx
        # sw_if_index: {"l34": [l34_acl_indxs], "l23": l23_acl_index }
        self.port_vpp_acls = defaultdict(dict)
        # keeps track of gpe locators and mapping info
        self.gpe_map = {'remote_map': {}}
        # key: sw if index in VPP; present when vhost-user is
        # connected and removed when we delete things.  May accumulate
        # any other VPP interfaces too, but that's harmless.
        self.iface_connected = set()

        self.vhost_ready_callback = None
        cb_event = self.vpp.CallbackEvents.VHOST_USER_CONNECT
        self.vpp.register_for_events(cb_event, self._vhost_ready_event)

        self.tap_wait_time = tap_wait_time
        self._external_taps = eventlet.Queue()
        eventlet.spawn(self._add_external_tap_worker)

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

    def ifup(self, ifidx):
        """Proxy for VPP's ifup."""
        self.vpp.ifup(ifidx)

    ########################################

    def get_if_for_physnet(self, physnet):
        """"Find (and mark used) the interface for a physnet"""
        ifname = self.physnets.get(physnet, None)
        if ifname is None:
            LOG.error('Physnet %s requested but not in config',
                      physnet)
            return None, None
        ifidx = self.vpp.get_ifidx_by_name(ifname)
        if ifidx is None:
            LOG.error('Physnet %s interface %s does not '
                      'exist in VPP', physnet, ifname)
            return None, None
        self.vpp.set_interface_tag(ifidx, physnet_if_tag(physnet))
        return ifname, ifidx

    def ensure_network_on_host(self, physnet, net_type, seg_id):
        """Find or create a network of the type required

        This assumes we are in sync and that therefore we know if
        this has already been done.
        """

        if (physnet, net_type, seg_id) not in self.networks:
            self.networks[(physnet, net_type, seg_id)] = \
                self.ensure_network_in_vpp(physnet, net_type, seg_id)
        return self.networks.get((physnet, net_type, seg_id), None)

    def ensure_network_in_vpp(self, physnet, net_type, seg_id):
        """Create a bridge referring to a network in VPP

        Returns information about the objects we set up in VPP.
        This will use anything it finds that looks like it
        relates to this network, so is idempotent.
        """

        intf, ifidx = self.get_if_for_physnet(physnet)
        if intf is None:
            LOG.error('Cannot create network because physnet'
                      '%s config is broken', physnet)
            return None

        # TODO(ijw): bridge domains have no distinguishing marks.
        # VPP needs to allow us to name or label them so that we
        # can find them when we restart.  If we add an interface
        # to two bridges that will likely not do as required

        if net_type == 'flat':
            if_uplink = ifidx

            LOG.debug('Adding uplink interface-idx:%s-%s to bridge '
                      'for flat networking', intf, if_uplink)
            bridge_idx = if_uplink
            self.ensure_interface_in_vpp_bridge(bridge_idx, if_uplink)

            # This interface has a physnet tag already.  Don't overwrite.

        elif net_type == 'vlan':
            LOG.debug('Adding uplink interface %s vlan %s '
                      'to bridge for vlan networking', intf, seg_id)
            # Besides the vlan sub-interface we need to also bring
            # up the primary uplink interface for Vlan networking
            self.vpp.ifup(ifidx)
            if_uplink = self.vpp.get_vlan_subif(intf, seg_id)
            if if_uplink is None:
                if_uplink = self.vpp.create_vlan_subif(ifidx, seg_id)
            # Our bridge IDs have one uplink interface in so we simply use
            # that ID as their domain ID
            # This means we can find them on resync from the tagged interface
            bridge_idx = if_uplink
            self.ensure_interface_in_vpp_bridge(bridge_idx, if_uplink)

            self.vpp.set_interface_tag(if_uplink,
                                       uplink_tag(physnet, net_type, seg_id))

            self.vpp.ifup(if_uplink)

        elif net_type == 'vxlan':
            # VXLAN bridges have no uplink interface at all.
            # We link the bridge directly to the GPE code.

            self.ensure_gpe_link()
            bridge_idx = self.bridge_idx_for_lisp_segment(seg_id)
            self.ensure_bridge_domain_in_vpp(bridge_idx)
            self.ensure_gpe_vni_to_bridge_mapping(seg_id, bridge_idx)

            # We attach the bridge to GPE without use of an uplink interface
            # as we affect forwarding in the bridge.
            if_uplink = None

        else:
            raise Exception('network type %s not supported', net_type)

        rv = {
            'physnet': physnet,
            'if_physnet': intf,
            'bridge_domain_id': bridge_idx,
            'network_type': net_type,
            'segmentation_id': seg_id,
        }

        if if_uplink is not None:
            self.vpp.ifup(if_uplink)
            rv['if_uplink_idx'] = if_uplink,

        return rv

    def delete_network_on_host(self, physnet, net_type, seg_id=None):
        net = self.networks.get((physnet, net_type, seg_id), None)
        if net is not None:

            self.vpp.delete_bridge_domain(net['bridge_domain_id'])
            if net['network_type'] == 'vlan':
                ifidx = net['if_uplink_idx']
                self.vpp.delete_vlan_subif(ifidx)
            elif net['network_type'] == 'vxlan':
                LOG.debug("Deleting vni %s from GPE map", seg_id)
                self.gpe_map[gpe_lset_name]['vnis'].remove(seg_id)
                # Delete all remote mappings corresponding to this VNI
                self.clear_remote_gpe_mappings(seg_id)
                # Delete VNI to bridge domain mapping
                self.delete_gpe_vni_to_bridge_mapping(seg_id,
                                                      net['bridge_domain_id']
                                                      )
                LOG.debug('Current gpe mapping %s', self.gpe_map)

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
    def _add_external_tap_worker(self):
        """Add an externally created TAP device to the bridge

        Wait for the external tap device to be created by the DHCP agent.
        When the tap device is ready, add it to bridge Run as a thread
        so REST call can return before this code completes its
        execution.
        """

        def _is_tap_configured(device_name, bridge, bridge_name):
            try:
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
                    return True
            except Exception as e:
                LOG.exception(e)
                # Something has gone bad, but we should not quit.
                pass
            return False

        pending_taps = []
        while True:
            # While we were working, check if new taps have been requested
            if not self._external_taps.empty():
                pending_taps.append(self._external_taps.get())
            elif len(pending_taps) == 0:
                # We have no work to do and blocking is now OK,
                # so wait on the empty external TAPs
                pending_taps.append(self._external_taps.get())

            for tap in pending_taps:
                (tap_timeout, dev_name, bridge, br_name) = tap
                if _is_tap_configured(dev_name, bridge, br_name):
                    pending_taps.remove(tap)
                elif time.time() > tap_timeout:
                    LOG.warning("Timeout for tap %s", dev_name)
                    pending_taps.remove(tap)

            # If we have more work, go for it straight away, otherwise
            # take a breather because the old tap state will take
            # time to change.
            if len(pending_taps) != 0:
                eventlet.sleep(2)

    def add_external_tap(self, device_name, bridge, bridge_name):
        """Enqueue tap info for the tap worker."""
        self._external_taps.put((time.time() + self.tap_wait_time,
                                 device_name, bridge, bridge_name))

    def _ensure_kernelside_plugtap(self, bridge_name, tap_name, int_tap_name):
        # This is the kernel-side config (and we should not assume
        # that, just because the interface exists in VPP, it has
        # been done previously - the crash could occur in the
        # middle of the process)
        # Running it twice is harmless.  Never running it is
        # problematic.

        # TODO(ijw): someone somewhere ought to be sorting
        # the MTUs out
        br = self.ensure_bridge(bridge_name)

        # This is the external TAP device that will be
        # created by Nova or an agent, say the DHCP agent
        # later in time.
        self.add_external_tap(tap_name, br, bridge_name)

        # This is the device that we just created with VPP
        if not br.owns_interface(int_tap_name):
            br.addif(int_tap_name)

    def ensure_interface_on_host(self, if_type, uuid, mac):
        if uuid in self.interfaces:
            # It's definitely there, we made it ourselves
            pass
        else:
            LOG.debug('creating port %s as type %s',
                      uuid, if_type)

            # Deal with the naming conventions of interfaces

            # TODO(ijw): naming not obviously consistent with
            # Neutron's naming
            tap_name = get_tap_name(uuid)

            if if_type == 'maketap':
                props = {'name': tap_name}
            elif if_type == 'plugtap':
                bridge_name = get_bridge_name(uuid)
                int_tap_name = get_vpptap_name(uuid)

                props = {'bridge_name': bridge_name,
                         'ext_tap_name': tap_name,
                         'int_tap_name': int_tap_name}
            elif if_type == 'vhostuser':
                path = get_vhostuser_name(uuid)
                props = {'path': path}
            else:
                raise UnsupportedInterfaceException(
                    'unsupported interface type')

            tag = port_tag(uuid)

            props['bind_type'] = if_type
            props['mac'] = mac

            iface_idx = self.vpp.get_ifidx_by_tag(tag)
            if iface_idx is not None:
                # The agent has at some point reset, but before the reset
                # this interface was at least created.  A previous sweep
                # will have ensured it's the right sort of interface.

                LOG.debug('port %s recovering existing port in VPP',
                          uuid)

            else:
                # Make an interface, and tag it for refinding.
                LOG.debug('binding port %s as type %s' %
                          (uuid, if_type))

                if if_type == 'maketap':
                    iface_idx = self.vpp.create_tap(tap_name, mac, tag)
                elif if_type == 'plugtap':
                    iface_idx = self.vpp.create_tap(int_tap_name, mac, tag)
                elif if_type == 'vhostuser':
                    iface_idx = self.vpp.create_vhostuser(path, mac, tag)

            if if_type == 'plugtap':
                # Plugtap interfaces belong in a kernel bridge, and we need
                # to monitor for the other side attaching.
                self._ensure_kernelside_plugtap(bridge_name,
                                                tap_name,
                                                int_tap_name)

            props['iface_idx'] = iface_idx
            self.interfaces[uuid] = props
        return self.interfaces[uuid]

    def ensure_interface_in_vpp_bridge(self, net_br_idx, iface_idx):
        self.ensure_bridge_domain_in_vpp(net_br_idx)
        # Adding an interface to a bridge does nothing if it's
        # already in there
        self.vpp.add_to_bridge(net_br_idx, iface_idx)

    def ensure_bridge_domain_in_vpp(self, bridge_idx):
        if bridge_idx not in self.vpp.get_bridge_domains():
            LOG.debug('Creating vpp bridge domain %s', bridge_idx)
            self.vpp.create_bridge_domain(bridge_idx, self.mac_age)

    def bind_interface_on_host(self, if_type, uuid, mac, physnet,
                               net_type, seg_id):
        """Configure the interface in VPP per the binding request.

        Because we may be restarting the agent on a VPP that is already
        running, do this defensively: interfaces that we do not know
        about may have had some of their binding done.  Acting in this
        way, we can be sure that the interface is now correctly bound
        regardless of what may have transpired previously.

        This may be called at any time because of a request from
        the mechanism driver, or it may be called during resync
        when state already exists in VPP but in either case we fix
        what we find and draw out from that a picture of the current
        state, including whether (in the case of vhostuser interfaces)
        the far end of the socket has attached to VPP.
        """

        # In order, we create the network bridge, the interface for
        # the far end, and we add it to the bridge.  Any of these
        # may have been done before; the functions we call correct
        # any previous state they find.

        net_data = self.ensure_network_on_host(physnet, net_type, seg_id)
        if net_data is None:
            LOG.error('port bind is not possible as physnet '
                      'could not be configured')
            # Returning None allows us to deal with the uplink
            # side of a failed binding in the caller.
            return None
        net_br_idx = net_data['bridge_domain_id']
        props = self.ensure_interface_on_host(if_type, uuid, mac)
        iface_idx = props['iface_idx']
        self.ensure_interface_in_vpp_bridge(net_br_idx, iface_idx)
        # Ensure local mac to VNI mapping for GPE
        if net_type == 'vxlan':
            self.add_local_gpe_mapping(seg_id, mac)
            LOG.debug('Current gpe mapping %s', self.gpe_map)
        props['net_data'] = net_data
        LOG.debug('Bound vpp interface with sw_idx:%s on '
                  'bridge domain:%s',
                  iface_idx, net_br_idx)
        return props

    def unbind_interface_on_host(self, uuid):
        """Detach an interface, clean up structures

        This removes and destroys the interface and the network
        if it is no longer used.

        This is *not* used in rebinding, as this requires the data
        we stored about an interface when it was bound.
        """
        if uuid not in self.interfaces:
            LOG.debug('unknown port %s unbinding request - ignored',
                      uuid)
        else:
            props = self.interfaces[uuid]
            self.clean_interface_from_vpp(uuid, props)

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

    def clean_interface_from_vpp(self, uuid, props):
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
            # This interface is no longer connected if it's deleted
            # RACE, as we may call unbind BEFORE the vhost user
            # interface is notified as connected to qemu
            if iface_idx in self.iface_connected:
                self.iface_connected.remove(iface_idx)
        elif props['bind_type'] in ['maketap', 'plugtap']:
            # remove port from bridge (sets to l3 mode) prior to deletion
            self.vpp.delete_from_bridge(iface_idx)
            self.vpp.delete_tap(iface_idx)
            if props['bind_type'] == 'plugtap':
                bridge_name = get_bridge_name(uuid)
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
        # If network_type=vxlan delete local vni to mac gpe mapping
        if props['net_data']['network_type'] == 'vxlan':
            mac = props['mac']
            seg_id = props['net_data']['segmentation_id']
            self.delete_local_gpe_mapping(seg_id, mac)
            LOG.debug('Current gpe mapping %s', self.gpe_map)
        self.interfaces.pop(uuid)

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
        """Adds/Replaces the secgroup ACL within VPP

        Arguments:
        secgroup - SecurityGroup NamedTuple object
        namedtuple('SecurityGroup', ['id', 'ingress_rules', 'egress_rules'])
        """
        # Default action == ADD if the acl indexes are set to ~0
        # VPP ACL indexes correspond to ingress and egress security
        # group rules
        in_acl_idx, out_acl_idx = \
            self.secgroups.get(secgroup.id,
                               VppAcl(0xffffffff, 0xffffffff))
        LOG.debug("secgroup_watcher:updating vpp input acl idx: %s and "
                  "output acl idx %s" % (in_acl_idx, out_acl_idx))

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

        in_acl_idx = self.vpp.acl_add_replace(acl_index=in_acl_idx,
                                              tag=secgroup_tag(secgroup.id,
                                                               VPP_TO_VM),
                                              rules=in_acl_rules,
                                              count=len(in_acl_rules))
        out_acl_idx = self.vpp.acl_add_replace(acl_index=out_acl_idx,
                                               tag=secgroup_tag(secgroup.id,
                                                                VM_TO_VPP),
                                               rules=out_acl_rules,
                                               count=len(out_acl_rules))
        LOG.debug("secgroup_watcher: in_acl_index:%s out_acl_index:%s "
                  "for secgroup:%s" % (in_acl_idx, out_acl_idx, secgroup.id))
        self.secgroups[secgroup.id] = VppAcl(in_acl_idx, out_acl_idx)
        LOG.debug("secgroup_watcher: current secgroup mapping: %s"
                  % self.secgroups)

    def acl_delete_on_host(self, secgroup):
        """Deletes the ingress and egress VPP ACLs on host for secgroup

        Arguments:
        secgroup - OpenStack security group ID
        """
        try:
            for acl_idx in self.secgroups[secgroup]:
                LOG.debug("secgroup_watcher: deleting VPP ACL %s for "
                          "secgroup %s" % (acl_idx, secgroup))
                self.vpp.acl_delete(acl_index=acl_idx)
            del self.secgroups[secgroup]
            LOG.debug("secgroup_watcher: current secgroup mapping: %s"
                      % self.secgroups)
        except KeyError:
            LOG.error("secgroup_watcher: received request to delete "
                      "an unknown security group %s" % secgroup)
        except Exception as e:
            LOG.error("Exception while deleting ACL %s" % e)

    def populate_secgroup_acl_mappings(self):
        """From vpp acl dump, populate the secgroups to VppACL mapping.

        Get a dump of existing vpp ACLs that are tagged, by tag
        Decode tag info
        populate secgroups data structure relating UUID of secgroup to ACL
        self.secgroups = {secgroup_id : VppAcl(in_idx, out_idx)}
        """
        LOG.debug("secgroup_watcher: Populating secgroup to VPP ACL map..")
        # Clear existing secgroups to ACL map for sanity
        LOG.debug("secgroup_watcher: Clearing existing secgroups "
                  "to vpp-acl mappings")

        self.secgroups = {}
        # Example of the acl_map data
        # acl_map: {'net-vpp.secgroup:<uuid>.from-vpp' : acl_idx
        #           'net-vpp.secgroup:<uuid>.to-vpp' : acl_idx,
        #           'net-vpp.common_spoof.from-vpp': acl_idx }
        acl_map = self.get_secgroup_acl_map()
        for item, acl_idx in acl_map.items():
            # Tags can be one of ours, or one something else set
            # decode_* functions attempt to match the tags to one of our
            # formats, and returns None if that's not a format it matches.

            secgroup_id, direction = decode_secgroup_tag(item)
            if secgroup_id is None:
                # Check if this is one of our common spoof ACL tag
                # If so, get the tag direction and set the secgroup_id to
                # COMMON_SPOOF_TAG so the correct spoof ACL can be read
                direction = decode_common_spoof_tag(item)
                if direction is not None:
                    # But it is a valid spoof tag
                    secgroup_id = COMMON_SPOOF_TAG
                    ingress = direction == VPP_TO_VM
            else:  # one of our valid secgroup ACL tag
                ingress = direction == VPP_TO_VM

            if secgroup_id is None:
                # This is neither a security group or a spoof
                # - so it's not installed by the mechdriver at all
                continue

            vpp_acl = self.secgroups.get(secgroup_id,
                                         VppAcl(0xffffffff, 0xffffffff))
            # secgroup_id will be missing first pass, and should be
            # completed on the second round through.
            if ingress:
                self.secgroups[secgroup_id] = vpp_acl._replace(
                    in_idx=acl_idx)
            else:
                self.secgroups[secgroup_id] = vpp_acl._replace(
                    out_idx=acl_idx)

            LOG.debug("secgroup_watcher: secgroup to VPP ACL mapping %s "
                      "constructed by reading "
                      "acl tags and building an acl_map %s"
                      % (self.secgroups, acl_map))

        if self.secgroups == {}:
            LOG.debug("secgroup_watcher: We have an empty secgroups "
                      "to acl mapping {}. Possible reason: vpp "
                      "may have been restarted on host.")

    def get_secgroup_acl_map(self):
        """Read VPP ACL tag data, construct and return an acl_map based on tag

        acl_map: {secgroup_tag : acl_idx}

        """
        acl_map = {}
        try:
            for acl_index, tag in self.vpp.get_acl_tags():
                # TODO(ijw): identify that this is one of our tags
                id, direction = decode_secgroup_tag(tag)
                if id is not None:
                    acl_map[tag] = acl_index
                else:
                    direction = decode_common_spoof_tag(tag)
                    if direction is not None:
                        acl_map[tag] = acl_index

                # Not all ACLs have tags, but ACLs we own will
                # have them and they will be decodeable.  Ignore
                # any externally created ACLs, they're not our problem.

            LOG.debug("secgroup_watcher: created acl_map %s from "
                      "vpp acl tags" % acl_map)
        except Exception as e:
            LOG.error("Exception getting acl_map from vpp acl tags %s" % e)
            raise
        return acl_map

    def maybe_set_acls_on_port(self, secgroup_ids, sw_if_index):
        """Compute a vector of input/output ACLs and set it on the VPP port.

        Arguments:
        secgroup_ids - OpenStack Security Group IDs
        sw_if_index - VPP software interface index on which the ACLs will
        be set

        This method checks the global secgroups to acl mapping to
        figure out the ACL indexes associated with the secgroup.  It
        then composes the acl vector and programs the port using vppf.

        If the secgroup cannot be found or if the ACL index is invalid
        i.e. 0xffffffff it will return False. This happens mostly in
        agent restart situations when the secgroups mapping is still
        being populated by the secgroup watcher thread, but since the
        port and secgroup threads are independent it can happen at any
        moment.

        """

        # A list of VppAcl namedtuples to be set on the port
        vpp_acls = []
        for secgroup_id in secgroup_ids:
            acl = self.secgroups.get(secgroup_id)
            # If any one or both indices are invalid wait for a valid acl
            if (not acl or
                    acl.in_idx == 0xFFFFFFFF or
                    acl.out_idx == 0xFFFFFFFF):
                LOG.debug("port_watcher: Waiting for a valid vpp acl "
                          "corresponding to secgroup %s" % secgroup_id)
                return False
            else:
                vpp_acls.append(acl)

        LOG.debug("port_watcher: setting vpp acls %s on port sw_if_index %s "
                  "for secgroups %s" % (vpp_acls, sw_if_index, secgroup_ids))
        self._set_acls_on_vpp_port(vpp_acls, sw_if_index)
        return True

    def _set_acls_on_vpp_port(self, vpp_acls, sw_if_index):
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
        self.vpp.set_acl_list_on_interface(sw_if_index=sw_if_index,
                                           count=len(acls),
                                           n_input=len(input_acls),
                                           acls=acls)
        LOG.debug("secgroup_watcher: Successfully set VPP acl vector %s "
                  "with n_input %s on sw_if_index %s"
                  % (acls, len(input_acls), sw_if_index))
        self.port_vpp_acls[sw_if_index]['l34'] = acls
        LOG.debug("secgroup_watcher: Current port acl_vector mappings %s"
                  % str(self.port_vpp_acls))

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
            """Return the IP Version i.e. 4 or 6"""
            return ip_network(unicode(ip)).version

        def _get_ip_prefix_length(ip):
            """Return the IP prefix length value

            Arguments:-
            ip - An ip IPv4 or IPv6 address (or) an IPv4 or IPv6 Network with
                 a prefix length
            If "ip" is an ip_address return its max_prefix_length
            i.e. 32 if IPv4 and 128 if IPv6
            if "ip" is an ip_network return its prefix_length
            """
            return ip_network(unicode(ip)).prefixlen

        src_mac_mask = _pack_mac('FF:FF:FF:FF:FF:FF')
        mac_ip_rules = []
        for mac, ip in mac_ips:  # ip can be an address (or) a network/prefix
            ip_version = _get_ip_version(ip)
            is_ipv6 = 1 if ip_version == 6 else 0
            ip_prefix = _get_ip_prefix_length(ip)
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
        self.vpp.set_macip_acl_on_interface(sw_if_index=sw_if_index,
                                            acl_index=acl_index,
                                            )
        LOG.debug("secgroup_watcher: Successfully set macip acl %s on "
                  "interface %s" % (acl_index,
                                    sw_if_index))
        if port_mac_ip_acl:  # Delete the previous macip ACL from VPP
            self.vpp.delete_macip_acl(acl_index=port_mac_ip_acl)
        self.port_vpp_acls[sw_if_index]['l23'] = acl_index

    def remove_acls_on_port(self, sw_if_index):
        """Removes all security group ACLs on the vpp port

        Arguments:-
        sw_if_index - Software index of the port on which ACLs are to be
                      removed
        """
        # We should know about the existing ACLS on port by looking up
        # port_vpp_acls. If there is a KeyError, we do not know about any
        # ACLs on that port. So ignore
        try:
            l3_acl_vector = self.port_vpp_acls[sw_if_index]['l34']
            LOG.debug("Deleting Layer3 ACL vector %s from if_idx %s",
                      l3_acl_vector, sw_if_index)
            self.vpp.delete_acl_list_on_interface(sw_if_index)
            del self.port_vpp_acls[sw_if_index]['l34']
        except KeyError:
            LOG.debug("No Layer3 ACLs are set on interface %s.. nothing "
                      "to delete", sw_if_index)

    def remove_mac_ip_acl_on_port(self, sw_if_index):
        """Removes all MAC/IP ACLs on the vpp port

        These ACLs correspond to anti-spoof and allowed-address-pair.

        Arguments:-
        sw_if_index - Software index of the port on which ACLs are to be
                      removed
        """
        try:
            l2_acl_index = self.port_vpp_acls[sw_if_index]['l23']
            LOG.debug("Deleting mac_ip acl %s from interface %s",
                      l2_acl_index, sw_if_index)
            self.vpp.delete_macip_acl_on_interface(sw_if_index, l2_acl_index)
            del self.port_vpp_acls[sw_if_index]['l23']
        except KeyError:
            LOG.debug("No mac_ip ACLs are set on interface %s.. nothing "
                      "to delete", sw_if_index)

    def spoof_filter_on_host(self):
        """Adds a spoof filter ACL on host if not already present.

        A spoof filter is identified by a common spoof tag mark.
        If not present create the filter on VPP, If it is present, replace
        it for good measure to ensure that the correct anti-spoof rules
        are always applied.

        Return: VppAcl(in_idx, out_idx)
        """
        # Check if we have an existing spoof filter deployed on vpp
        spoof_acl = self.secgroups.get(COMMON_SPOOF_TAG)
        # Get the current anti-spoof filter rules. If a spoof filter is
        # present replace rules for good measure, else create a new
        # spoof filter
        spoof_filter_rules = self.get_spoof_filter_rules()
        if spoof_acl:
            LOG.debug("secgroup_watcher: replacing existing spoof acl "
                      "indices [in_idx, out_idx] = %s with rules %s",
                      [spoof_acl.in_idx, spoof_acl.out_idx],
                      spoof_filter_rules)
            in_acl_idx, out_acl_idx = spoof_acl.in_idx, spoof_acl.out_idx
        else:
            LOG.debug("secgroup_watcher: adding a new spoof filter acl "
                      "with rules %s", spoof_filter_rules)
            in_acl_idx = out_acl_idx = 0xffffffff

        in_acl_idx = self.vpp.acl_add_replace(
            acl_index=in_acl_idx,
            tag=common_spoof_tag(VPP_TO_VM),
            rules=spoof_filter_rules['ingress'],
            count=len(spoof_filter_rules['ingress'])
            )

        out_acl_idx = self.vpp.acl_add_replace(
            acl_index=out_acl_idx,
            tag=common_spoof_tag(VM_TO_VPP),
            rules=spoof_filter_rules['egress'],
            count=len(spoof_filter_rules['egress'])
            )
        LOG.debug("secgroup_watcher: in_acl_index:%s out_acl_index:%s "
                  "for the current spoof filter", in_acl_idx, out_acl_idx)
        # Add the new spoof ACL to secgroups mapping if it is valid
        if (in_acl_idx != 0xFFFFFFFF
                and out_acl_idx != 0xFFFFFFFF and not spoof_acl):
            spoof_acl = VppAcl(in_acl_idx, out_acl_idx)
            LOG.debug("secgroup_watcher: adding a new spoof_acl %s to "
                      "secgroups mapping %s", str(spoof_acl), self.secgroups)
            self.secgroups[COMMON_SPOOF_TAG] = spoof_acl
            LOG.debug("secgroup_watcher: current secgroup mapping: %s",
                      self.secgroups)
        return spoof_acl

    def _pack_address(self, ip_addr):
        """Pack an IPv4 or IPv6 (ip_addr or ip_network) into binary.

        If the argument is an ip_address, it is packed and if the argument is
        an ip_network only the network portion of it is packed
        Arguments:-
        ip_addr: an IPv4 or IPv6 address without a prefix_length e.g. 1.1.1.1
                                  (or)
                 an IPv4 or IPv6 network with prefix_length e.g. 1.1.1.0/24
        """
        # Works for both addresses and the net address of masked networks
        return ip_network(unicode(ip_addr)).network_address.packed

    def _get_snat_indexes(self, floatingip_dict):
        """Return the internal and external SNAT interface indexes.

        If needed the external subinterface will be created.
        """

        # Get internal network details.
        internal_network_data = self.networks.get(
            (floatingip_dict['physnet'],
             floatingip_dict['internal_net_type'],
             floatingip_dict['internal_segmentation_id']),
            None)
        if internal_network_data:
            net_br_idx = internal_network_data['bridge_domain_id']

            # if needed the external subinterface will be created.
            external_network_data = self.ensure_network_on_host(
                floatingip_dict['physnet'],
                floatingip_dict['external_net_type'],
                floatingip_dict['external_segmentation_id'])

            # Return the internal and external interface indexes.
            return (self.vpp.get_bridge_bvi(net_br_idx),
                    external_network_data['if_uplink_idx'])
        else:
            LOG.error('Failed to get internal network data. Verify that the '
                      'router interface on the private network was created.')
            return None, None

    def _delete_external_subinterface(self, floatingip_dict):
        """Check if the external subinterface can be deleted."""

        physnet = floatingip_dict['physnet']
        external_net_type = floatingip_dict['external_net_type']
        external_segmentation_id = floatingip_dict['external_segmentation_id']
        external_network_data = self.networks.get(
            (physnet, external_net_type, external_segmentation_id), None)
        if external_network_data:
            physnet_ip_addrs = self.vpp.get_interface_ip_addresses(
                external_network_data['if_uplink_idx'])
            if not physnet_ip_addrs:
                self.delete_network_on_host(
                    physnet, external_net_type, external_segmentation_id)

    def _get_external_vlan_subif(self, if_name, if_idx, seg_id):
        sub_if = self.vpp.get_vlan_subif(if_name, seg_id)
        if not sub_if:
            # Create a VLAN subif
            sub_if = self.vpp.create_vlan_subif(if_idx, seg_id)
            self.vpp.ifup(sub_if)

        return sub_if

    def create_router_external_gateway_on_host(self, router):
        """Creates the external gateway for the router.

        Add the specified external gateway IP address as a SNAT
        external IP address within the router's VRF.
        """
        if_name, if_idx = self.get_if_for_physnet(router['external_physnet'])
        # Set the external physnet/subif as a SNAT outside interface
        if router['external_net_type'] == p_const.TYPE_VLAN:
            if_idx = self._get_external_vlan_subif(
                if_name, if_idx, router['external_segment'])
        elif router['external_net_type'] == p_const.TYPE_FLAT:
            # Use the ifidx grabbed earlier
            pass
        else:
            # Unsupported segmentation type
            LOG.debug("Unsupported segmentation type for external networks %s",
                      router['external_net_type'])
            return False

        # Check if this interface is already set to outside
        intf_list = self.vpp.get_snat_interfaces()
        if if_idx not in intf_list:
            self.vpp.set_snat_on_interface(if_idx, is_inside=0)

        # Grab all snat and physnet addresses
        addrs = self.vpp.get_snat_addresses()
        physnet_ip_addrs = self.vpp.get_interface_ip_addresses(if_idx)

        for addr in router['gateways']:
            if addr[0] not in addrs:
                self.vpp.add_del_snat_address(
                    self._pack_address(addr[0]), router['vrf_id'])

            # Set the Subnet gateway as external network gateway address
            # Check if this address is already set on the external
            if str(addr[0]) not in [ip[0] for ip in physnet_ip_addrs]:
                # Set this itnerface to VRF 0
                self.vpp.set_interface_vrf(if_idx, 0)
                self.vpp.set_interface_ip(
                    if_idx, self._pack_address(addr[0]), int(addr[1]))

    def delete_router_external_gateway_on_host(self, router):
        """Delete the external IP address from the router.

        Deletes the specified external gateway IP address from the
        SNAT external IP pool from this router's VRF.
        """
        if_name, if_idx = self.get_if_for_physnet(router['external_physnet'])
        if router['external_net_type'] == p_const.TYPE_VLAN:
            if_idx = self.vpp.get_vlan_subif(
                if_name, router['external_segment'])
        elif router['external_net_type'] == p_const.TYPE_FLAT:
            # Use physnet id_idx found earlier
            pass
        else:
            # Unsupported type
            LOG.debug("Unsupported segmentation type for external networks %s",
                      router['external_net_type'])
            return False

        # Grab all snat and physnet addresses
        addrs = self.vpp.get_snat_addresses()
        if if_idx:
            physnet_ip_addrs = self.vpp.get_interface_ip_addresses(if_idx)

        for addr in router['gateways']:
            # Delete external snat addresses for the router
            if addr[0] in addrs:
                self.vpp.add_del_snat_address(
                    self._pack_address(addr[0]), router['vrf_id'],
                    is_add=False)

            # Delete router external gateway from external interface
            if if_idx:
                if str(addr[0]) in [ip[0] for ip in physnet_ip_addrs]:
                    self.vpp.del_interface_ip(
                        if_idx, self._pack_address(addr[0]), int(addr[1]))

        # Delete the subinterface if type VLAN
        if router['external_net_type'] == p_const.TYPE_VLAN and if_idx:
            self.vpp.delete_vlan_subif(if_idx)

    def create_router_interface_on_host(self, router):
        """Create a router on the local host.

        Creates a loopback interface and sets the bridge's BVI to the
        loopback interface to act as an L3 gateway for the bridge network.
        """
        net_data = self.ensure_network_on_host(
            router['physnet'], router['net_type'], router['segmentation_id'])
        net_br_idx = net_data['bridge_domain_id']
        # Get a list of all SNAT interfaces
        int_list = self.vpp.get_snat_interfaces()
        # Check if a loopback is already set as the BVI for this bridge
        br_bvi = self.vpp.get_bridge_bvi(net_br_idx)
        if br_bvi:
            # Grab the BVI interface index
            loopback_idx = br_bvi
        else:
            loopback_idx = self.vpp.create_loopback(router['loopback_mac'])
            self.vpp.set_loopback_bridge_bvi(loopback_idx, net_br_idx)
            self.vpp.set_interface_vrf(loopback_idx, router['vrf_id'],
                                       router['is_ipv6'])
            # MTU setting could be turned off in the config, make a best
            # effort to set it in that case
            try:
                self.vpp.set_interface_mtu(loopback_idx, router['mtu'])
            except SystemExit:
                # Log error and continue, do not exit here
                LOG.error("Error setting MTU on router interface")

            # Set this BVI as an inside SNAT interface
            # Only if it's not already set
            if loopback_idx not in int_list:
                self.vpp.set_snat_on_interface(loopback_idx)

        # Check if the BVI interface has the IP address for this
        # subnet's gateway
        addresses = self.vpp.get_interface_ip_addresses(loopback_idx)
        found = False
        for address in addresses:
            if address[0] == str(router['gateway_ip']):
                found = True
                break

        if not found:
            # Add this IP address to this BVI interface
            self.vpp.set_interface_ip(loopback_idx,
                                      self._pack_address(router['gateway_ip']),
                                      router['prefixlen'], router['is_ipv6'])
        return loopback_idx

    def delete_router_interface_on_host(self, router):
        """Deletes a router from the host.

        Deletes a loopback interface from the host, this removes the BVI
        interface from the local bridge.
        """
        net_data = self.ensure_network_on_host(
            router['physnet'], router['net_type'], router['segmentation_id'])
        net_br_idx = net_data['bridge_domain_id']
        bvi_if_idx = self.vpp.get_bridge_bvi(net_br_idx)
        # Get bvi interface from bridge details
        if bvi_if_idx:
            # Get all IP's assigned to the BVI interface
            addresses = self.vpp.get_interface_ip_addresses(bvi_if_idx)
            if len(addresses) > 1:
                # Dont' delete the BVI, only remove one IP from it
                self.vpp.del_interface_ip(
                    bvi_if_idx, self._pack_address(router['gateway_ip']),
                    router['prefixlen'], router['is_ipv6'])
            else:
                # Last subnet assigned, delete the interface
                self.vpp.delete_loopback(bvi_if_idx)

    def associate_floatingip(self, floatingip_dict):
        """Add the VPP configuration to support One-to-One SNAT."""

        # If needed, add the SNAT interfaces.
        loopback_idx, external_idx = self._get_snat_indexes(floatingip_dict)
        snat_interfaces = self.vpp.get_snat_interfaces()

        if loopback_idx and loopback_idx not in snat_interfaces:
            self.vpp.set_snat_on_interface(loopback_idx)
        if external_idx and external_idx not in snat_interfaces:
            self.vpp.set_snat_on_interface(external_idx, is_inside=0)

        # If needed, add the SNAT internal and external IP address mapping.
        snat_local_ipaddresses = self.vpp.get_snat_local_ipaddresses()
        if floatingip_dict['fixed_ip_address'] not in snat_local_ipaddresses:
            self.vpp.set_snat_static_mapping(
                floatingip_dict['fixed_ip_address'],
                floatingip_dict['floating_ip_address'])

    def disassociate_floatingip(self, floatingip_dict):
        """Remove the VPP configuration used by One-to-One SNAT."""

        # Delete the SNAT internal and external IP address mapping.
        snat_local_ipaddresses = self.vpp.get_snat_local_ipaddresses()
        if floatingip_dict['fixed_ip_address'] in snat_local_ipaddresses:
            self.vpp.set_snat_static_mapping(
                floatingip_dict['fixed_ip_address'],
                floatingip_dict['floating_ip_address'],
                is_add=0)

        # Delete the SNAT interfaces if all IP addresses have been removed
        # and determine if external subinterface can be deleted.
        loopback_idx, external_idx = self._get_snat_indexes(floatingip_dict)
        snat_local_ipaddresses = self.vpp.get_snat_local_ipaddresses()
        if not snat_local_ipaddresses:
            if loopback_idx:
                self.vpp.set_snat_on_interface(loopback_idx, is_add=0)
            self.vpp.set_snat_on_interface(external_idx, is_inside=0, is_add=0)
            self._delete_external_subinterface(floatingip_dict)

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
            # Permit TCP port 80 traffic to 169.254.169.254/32 for metadata
            _compose_rule(1, 0, '0.0.0.0', 0, '169.254.169.254', 32,
                          6, 0, 65535, 80, 80),
            ]

        return {'ingress': ingress_rules,
                'egress': egress_rules}

    def get_macip_acl_dump(self):
        """Get a dump of macip ACLs on the node"""
        return self.vpp.get_macip_acl_dump()

# ################## BEGIN LISP GPE Methods #################################
    def bridge_idx_for_lisp_segment(self, seg_id):
        """Generate a bridge domain index for GPE overlay networking

        Use the 65K namespace for GPE bridge-domains to avoid conflicts
        with other bridge domains and return a unique BD per network segment
        """
        return 65000 + seg_id

    def ensure_gpe_vni_to_bridge_mapping(self, seg_id, bridge_idx):
        # Add eid table mapping: vni to bridge-domain
        if (seg_id, bridge_idx) not in self.vpp.get_lisp_vni_to_bd_mappings():
            LOG.debug("Adding GPE VNI-BD mapping for vni %s and bridge-"
                      "domain %s", seg_id, bridge_idx)
            self.vpp.add_lisp_vni_to_bd_mapping(vni=seg_id,
                                                bridge_domain=bridge_idx)

    def delete_gpe_vni_to_bridge_mapping(self, seg_id, bridge_idx):
        # Remove vni to bridge-domain mapping in VPP if present
        if (seg_id, bridge_idx) in self.vpp.get_lisp_vni_to_bd_mappings():
            LOG.debug("Deleting vni %s to bridge-domain %s GPE mapping",
                      seg_id, bridge_idx)
            self.vpp.del_lisp_vni_to_bd_mapping(vni=seg_id,
                                                bridge_domain=bridge_idx)

    def ensure_remote_gpe_mapping(self, vni, mac, remote_ip):
        """Ensures a remote GPE mapping

        A remote GPE mapping contains a remote mac-address, vni and the
        underlay ip address of the remote node (i.e. remote_ip)
        """
        if (mac, vni) not in self.gpe_map['remote_map']:
            LOG.debug("Adding remote gpe mapping for mac:%s, vni:%s to "
                      "remote underlay ip: %s", mac, vni, remote_ip)
            is_ip4 = 1 if ip_network(unicode(remote_ip)).version == 4 else 0
            remote_locator = {"is_ip4": is_ip4,
                              "priority": 1,
                              "weight": 1,
                              "addr": self._pack_address(remote_ip)
                              }
            self.vpp.add_lisp_remote_mac(mac, vni, remote_locator)
            self.gpe_map['remote_map'][(mac, vni)] = remote_ip

    def delete_remote_gpe_mapping(self, vni, mac):
        """Delete a remote GPE vni to mac mapping."""
        if (mac, vni) in self.gpe_map['remote_map']:
            LOG.debug("Deleting remote gpe mapping for mac:%s, vni:%s to "
                      "remote underlay ip: %s", mac, vni,
                      self.gpe_map['remote_map'][(mac, vni)])
            self.vpp.del_lisp_remote_mac(mac, vni)
            del self.gpe_map['remote_map'][(mac, vni)]

    def add_local_gpe_mapping(self, vni, mac):
        """Add a local GPE mapping between a mac and vni."""
        lset_mapping = self.gpe_map[gpe_lset_name]
        LOG.debug('Adding vni %s to gpe_map', vni)
        lset_mapping['vnis'].add(vni)
        if mac not in lset_mapping['local_map']:
            LOG.debug('Adding a local gpe mapping for mac:%s & vni:%s in '
                      'locator_set %s', mac, vni, gpe_lset_name)
            self.vpp.add_lisp_local_mac(mac, vni, gpe_lset_name)
            lset_mapping['local_map'][mac] = vni

    def delete_local_gpe_mapping(self, vni, mac):
        LOG.debug('Deleting a local gpe mapping in locator set %s for '
                  'mac: %s and vni %s', gpe_lset_name, mac, vni)
        lset_mapping = self.gpe_map[gpe_lset_name]
        if mac in lset_mapping['local_map']:
            self.vpp.del_lisp_local_mac(mac, vni, gpe_lset_name)
            del self.gpe_map[gpe_lset_name]['local_map'][mac]

    def clear_remote_gpe_mappings(self, segmentation_id):
        """Clear all GPE mac to seg_id remote mappings for the seg_id.

        When a segment is unbound from a host, all remote GPE mappings for
        that segment are cleared.
        """
        LOG.debug("Clearing all gpe remote mappings for VNI:%s",
                  segmentation_id)
        for mac_vni_tpl in self.gpe_map['remote_map'].keys():
            mac, vni = mac_vni_tpl
            if segmentation_id == vni:
                self.delete_remote_gpe_mapping(vni, mac)

    def ensure_gpe_link(self):
        """Ensures that the GPE uplink interface is present and configured.

        Returns:-
        The software_if_index of the GPE uplink functioning as the underlay
        """
        intf, if_physnet = self.get_if_for_physnet(self.gpe_locators)
        LOG.debug('Setting vxlan gpe underlay attachment interface: %s',
                  intf)
        if if_physnet is None:
            LOG.error('Cannot create a vxlan GPE network because the gpe_'
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
        self.vpp.set_interface_address(
            sw_if_index=if_physnet,
            is_ipv6=1 if ip_network(unicode(self.gpe_underlay_addr)
                                    ).version == 6 else 0,
            address_length=int(self.gpe_underlay_mask),
            address=self._pack_address(self.gpe_underlay_addr)
            )
        return (intf, if_physnet)

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
        LOG.debug("Current gpe locator indices: %s", locator_indices)
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

######################################################################

LEADIN = '/networking-vpp'  # TODO(ijw): make configurable?
ROUTER_DIR = 'routers/router/'
ROUTER_INTF_DIR = 'routers/interface/'
ROUTER_FIP_DIR = 'routers/floatingip/'


class EtcdListener(object):
    def __init__(self, host, client_factory, vppf, physnets):
        self.host = host
        self.client_factory = client_factory
        self.vppf = vppf
        self.physnets = physnets
        self.pool = eventlet.GreenPool()
        self.secgroup_enabled = cfg.CONF.SECURITYGROUP.enable_security_group

        # These data structures are used as readiness indicators.
        # A port is only in here only if the attachment part of binding
        # has completed.
        # key: if index in VPP; value: (ID, bound-callback, vpp-prop-dict)
        self.iface_state = {}

        # Members of this are ports requiring security groups with unsatisfied
        # requirements.
        self.iface_awaiting_secgroups = {}

        # We also need to know if the vhostuser interface has seen a socket
        # connection: this tells us there's a state change, and there is
        # a state detection function on self.vppf.
        self.vppf.vhost_ready_callback = self._vhost_ready

    def unbind(self, id):
        self.vppf.unbind_interface_on_host(id)

    def bind(self, bound_callback, id, binding_type, mac_address, physnet,
             network_type, segmentation_id, security_data):
        """Bind an interface as instructed by ML2 on this host.

        The interface as a network and binding type.  Assuming the
        network as been dropped onto the physnet specified, bind
        that uplink to the interface in question by creating an
        interface of the appropriate form and propagating the network
        to it.

        This call also identifies if we should consider the interface
        fully up.  This may happen now, or, asynchronously, later,
        depending on whether all the prerequisites are in place.  That
        includes the behaviour of whatever's on the other end of the
        interface.
        """
        # args['binding_type'] in ('vhostuser', 'plugtap'):
        # For GPE, fetch remote mappings from etcd for any "new" network
        # segments we will be binding to so we are aware of all the remote
        # overlay (mac) to underlay (IP) values
        if network_type == 'vxlan':
            # For vxlan-gpe, a physnet value is not messaged by ML2 as it
            # is not specified for creating a gpe tenant network. Hence for
            # these net types we replace the physnet with the value of
            # gpe_locators, which stand for the physnet name.
            physnet = self.vppf.gpe_locators
            self.ensure_gpe_remote_mappings(segmentation_id)
        props = self.vppf.bind_interface_on_host(binding_type,
                                                 id,
                                                 mac_address,
                                                 physnet,
                                                 network_type,
                                                 segmentation_id)
        if props is None:
            # Problems with the binding
            # We will never notify anyone this port is ready.
            return None
        # Store the binding information.  We put this into
        # etcd when the interface comes up to show that things
        # are ready and expose it to curious operators, who may
        # be able to debug with it.  This may not happen
        # immediately because the far end may not have connected.
        iface_idx = props['iface_idx']

        port_security_enabled = security_data.get('port_security_enabled',
                                                  True)

        if port_security_enabled:
            self.iface_awaiting_secgroups[iface_idx] = \
                security_data.get('security_groups', [])
        else:
            self.iface_awaiting_secgroups[iface_idx] = []

        self.iface_state[iface_idx] = (id, bound_callback, props)

        self.apply_spoof_macip(iface_idx, security_data)

        self.maybe_apply_secgroups(iface_idx)

    def apply_spoof_macip(self, iface_idx, security_data):
        """Apply non-secgroup security to a port

        This is an idempotent function to set up the port security
        (antispoof and allowed-address-pair) that can be determined
        solely from the data on the port itself.

        """

        (id, bound_callback, props) = self.iface_state[iface_idx]

        # TODO(ijw): this is a convenience for spotting L3 and DHCP
        # ports, but it's not the right way
        is_secured_port = props['bind_type'] == 'vhostuser'

        port_security_enabled = security_data.get('port_security_enabled',
                                                  True)

        # If (security-groups and port_security)
        # are enabled and it's a vhostuser port
        # proceed to set L3/L2 ACLs, else skip security
        if (self.secgroup_enabled and
                port_security_enabled and
                is_secured_port):

            # Set Allowed address pairs and mac-spoof filter
            aa_pairs = security_data.get('allowed_address_pairs', [])
            LOG.debug("port_watcher: Setting allowed "
                      "address pairs %s on port %s "
                      "sw_if_index %s" %
                      (aa_pairs,
                       id,
                       iface_idx))
            self.set_mac_ip_acl_on_port(
                security_data['mac_address'],
                security_data.get('fixed_ips'),
                aa_pairs,
                iface_idx)
        else:
            self.vppf.remove_mac_ip_acl_on_port(iface_idx)

    def reconsider_port_secgroups(self):
        """Check current port security state.

        See if any of the ports awaiting security group ACL population can
        now be secured.
        """

        # TODO(ijw): could be more efficient in selecting ports to check
        for iface_idx in self.iface_awaiting_secgroups.keys():
            self.maybe_apply_secgroups(iface_idx)

    def maybe_apply_secgroups(self, iface_idx):

        """Apply secgroups to a port if all constructs are available

        This is an idempotent function to set up port security.  It
        relies on the pre-existence of the ACLs corresponding to
        security groups, so it may or may not be possible to apply
        security at this moment in time.  If it is, the port is
        recorded as secure (allowing binding to complete), and if it
        isn't we will attempt to reapply as more security groups are
        created.

        It is reapplied if the security group list changes on the
        port.  It is not reapplied if the security group content is
        changed, because the ACL number remains the same and therefore
        so does the port config.

        """

        secgroup_ids = self.iface_awaiting_secgroups[iface_idx]

        (id, bound_callback, props) = self.iface_state[iface_idx]

        # TODO(ijw): this is a convenience for spotting L3 and DHCP
        # ports, but it's not the right way
        is_secured_port = props['bind_type'] == 'vhostuser'

        # If security-groups are enabled and it's a port needing
        # security proceed to set L3/L2 ACLs, else skip security
        if (self.secgroup_enabled and
                is_secured_port and
                secgroup_ids != []):
            LOG.debug("port_watcher:Setting secgroups %s "
                      "on sw_if_index %s for port %s" %
                      (secgroup_ids,
                       props['iface_idx'],
                       id))
            if not self.vppf.maybe_set_acls_on_port(
                    secgroup_ids,
                    iface_idx):
                # The ACLs for secgroups are not yet ready
                # Leave ourselves in the pending list
                return

        else:
            LOG.debug("Clearing port_security on "
                      "port %s", id)
            self.vppf.remove_acls_on_port(
                props['iface_idx'])

        # Remove with no error if not present
        self.iface_awaiting_secgroups.pop(iface_idx, None)

        self.maybe_up(iface_idx)

    def _vhost_ready(self, sw_if_index):
            self.maybe_up(sw_if_index)

    def maybe_up(self, iface_idx):
        """Flag that an interface is connected, if it is

        This is a combination of 'we did our bit' and 'the other
        end connected'.  These can happen in either order; if
        we resync, we recheck our binding but the other end
        may have connected already.

        This both tells Nova the interface is ready and brings the
        interface up in VPP.

        There is nothing wrong (other than a bit of inefficiency)
        in sending this to Nova multiple times; the watching driver may
        see the key write multiple times and will act accordingly.
        """

        if iface_idx not in self.iface_state:
            # Binding hasn't completed
            return

        (id, bound_callback, props) = self.iface_state[iface_idx]

        if (props['bind_type'] == 'vhostuser' and
                not self.vppf.vhostuser_linked_up(iface_idx)):
            # vhostuser connection that hasn't yet found a friend
            return

        if iface_idx in self.iface_awaiting_secgroups:
            return

        LOG.debug('marking index %s as ready', id)

        self.vppf.ifup(iface_idx)
        bound_callback(id, props)

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

    def spoof_filter_on_host(self):
        """Deploy anti-spoofing ingress and egress ACLs on VPP.

        Tag ingress spoof acl on VPP with ID: FFFF:0
        Tag egress spoof acl on VPP with ID: FFFF:1
        Add Spoof ACL mapping with Key: "FFFF"
                                   Val: VppAcl(in_idx, out_idx)
        to secgroups mapping
        """
        self.vppf.spoof_filter_on_host()

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
        self.vppf.set_mac_ip_acl_on_vpp_port(mac_ips, sw_if_index)

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

# #################### LISP GPE Methods ###############################
    def is_valid_remote_map(self, vni, host):
        """Return True if the remote map is valid else False.

        A remote mapping is valid only if we bind a port on the vni
        Ignore all the other remote mappings as the host doesn't care
        """
        if host != self.host and vni in self.vppf.gpe_map[gpe_lset_name][
            'vnis']:
            return True
        else:
            return False

    def fetch_remote_gpe_mappings(self, vni):
        """Fetch and add all remote mappings from etcd for the vni"""
        key_space = self.gpe_key_space + "/%s" % vni
        LOG.debug("Fetching remote gpe mappings for vni:%s", vni)
        rv = self.client_factory.client().read(key_space, recursive=True)
        for child in rv.children:
            m = re.match(key_space + '/([^/]+)' + '/([^/]+)', child.key)
            if m:
                hostname = m.group(1)
                mac = m.group(2)
                if self.is_valid_remote_map(vni, hostname):
                    self.vppf.ensure_remote_gpe_mapping(vni, mac, child.value)

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
        lset_data = self.vppf.gpe_map[gpe_lset_name]
        # Fetch and add remote mappings only for "new" segments that we do
        # not yet know of, but will be binding to shortly as requested by ML2
        if segmentation_id not in lset_data['vnis']:
            lset_data['vnis'].add(segmentation_id)
            bridge_idx = self.vppf.bridge_idx_for_lisp_segment(segmentation_id)
            self.vppf.ensure_bridge_domain_in_vpp(bridge_idx)
            self.vppf.ensure_gpe_vni_to_bridge_mapping(segmentation_id,
                                                       bridge_idx)
            self.fetch_remote_gpe_mappings(segmentation_id)

    AGENT_HEARTBEAT = 60  # seconds

    def process_ops(self):
        # TODO(ijw): needs to remember its last tick on reboot, or
        # reconfigure from start (which means that VPP needs it
        # storing, so it's lost on reboot of VPP)

        self.port_key_space = LEADIN + "/nodes/%s/ports" % self.host
        self.router_key_space = LEADIN + "/nodes/%s/routers" % self.host
        self.secgroup_key_space = LEADIN + "/global/secgroups"
        self.state_key_space = LEADIN + "/state/%s/ports" % self.host
        self.physnet_key_space = LEADIN + "/state/%s/physnets" % self.host
        self.gpe_key_space = LEADIN + "/global/networks/gpe"

        etcd_client = self.client_factory.client()
        etcd_helper = nwvpp_utils.EtcdHelper(etcd_client)
        # We need certain directories to exist so that we can write to
        # and watch them
        etcd_helper.ensure_dir(self.port_key_space)
        etcd_helper.ensure_dir(self.secgroup_key_space)
        etcd_helper.ensure_dir(self.state_key_space)
        etcd_helper.ensure_dir(self.physnet_key_space)
        etcd_helper.ensure_dir(self.router_key_space)
        etcd_helper.ensure_dir(self.gpe_key_space)

        etcd_helper.clear_state(self.state_key_space)

        physnets = self.physnets.keys()
        etcd_helper.clear_state(self.physnet_key_space)
        for f in physnets:
            etcd_client.write(self.physnet_key_space + '/' + f, 1)

        # We need to be wary not to hand the same client to multiple threads;
        # this etcd_helper and client dies here
        etcd_helper = None
        etcd_client = None

        # load sw_if_index to macip acl index mappings
        self.load_macip_acl_mapping()
        if 'vxlan' in cfg.CONF.ml2.type_drivers:
            self.vppf.load_gpe_mappings()

        self.binder = BindNotifier(self.client_factory, self.state_key_space)
        self.pool.spawn(self.binder.run)

        class PortWatcher(EtcdChangeWatcher):

            def do_tick(self):
                # The key that indicates to people that we're alive
                # (not that they care)
                # TODO(ijw): use refresh after the create to avoid the
                # notification
                self.etcd_client.write(LEADIN + '/state/%s/alive' %
                                       self.data.host,
                                       1, ttl=3 * self.heartbeat)

            def removed(self, port):
                # Removing key == desire to unbind

                try:
                    port = self.data.vppf.interfaces[port]
                    port_net = port['net_data']
                    is_vxlan = port_net['network_type'] == 'vxlan'

                    if is_vxlan:
                        # Get seg_id and mac to delete any gpe mappings
                        seg_id = port_net['segmentation_id']
                        mac = port['mac']
                except KeyError:
                    # On initial resync, this information may not
                    # be available; also, the network may not
                    # be vxlan
                    if is_vxlan:
                        LOG.warn('Unable to delete GPE mappings for port')
                    is_vxlan = False

                self.data.unbind(port)

                # Unlike bindings, unbindings are immediate.

                try:
                    self.etcd_client.delete(
                        self.data.state_key_space + '/%s'
                        % port)
                    if is_vxlan:
                        self.etcd_client.delete(
                            self.data.gpe_key_space + '/%s/%s/%s'
                            % (seg_id, self.data.host, mac))
                except etcd.EtcdKeyNotFound:
                    # Gone is fine; if we didn't delete it
                    # it's no problem
                    pass

            def added(self, port, value):
                # Create or update == bind

                # In EtcdListener, bind *ensures correct
                # binding* and is idempotent.  It will also
                # fix up security if the security state has
                # changed.  NB most things will not change on
                # an update.

                data = json.loads(value)
                self.data.bind(
                    self.data.binder.add_notification,
                    port,
                    data['binding_type'],
                    data['mac_address'],
                    data['physnet'],
                    data['network_type'],
                    data['segmentation_id'],
                    data  # TODO(ijw) convert incoming to security fmt
                    )
                # While the bind might fail for one reason or another,
                # we have nothing we can do at this point.  We simply
                # decline to notify Nova the port is ready.

                # For vxlan networks,
                # write the remote mapping data to etcd to
                # propagate the mac to underlay mapping to all
                # agents that bind this segment using GPE
                if data['network_type'] == 'vxlan':
                    host_ip = self.data.vppf.gpe_underlay_addr
                    gpe_key = self.data.gpe_key_space + '/%s/%s/%s' % (
                        data['segmentation_id'],
                        self.data.host,
                        data['mac_address'])
                    LOG.debug('Writing gpe key %s with vxlan mapping '
                              'to underlay IP address %s',
                              gpe_key, host_ip)
                    self.etcd_client.write(gpe_key, host_ip)

        class RouterWatcher(EtcdChangeWatcher):
            """Start an etcd watcher for router operations.

            Starts an etcd watcher on the /router directory for
            this node. This watcher is responsible for consuming
            Neutron router CRUD operations.
            """
            def do_tick(self):
                pass

            def _del_key(self, key):
                try:
                    self.etcd_client.delete(key)
                except etcd.EtcdKeyNotFound:
                    # Gone is fine; if we didn't delete it
                    # it's no problem
                    pass

            def key_change(self, action, key, value):
                LOG.debug("router_watcher: doing work for %s %s %s" %
                          (action, key, value))
                m = re.match(self.data.router_key_space + '/([^/]+)/([^/]+)?$',
                             key)
                if m and m.group(1) == 'interface':
                    if action != 'delete':
                        router_id = m.group(2)
                        router = json.loads(value)
                        if router.get('delete', False):
                            self.data.vppf.delete_router_interface_on_host(
                                router)
                            self._del_key(self.data.router_key_space +
                                          '/interface/%s' % router_id)
                        else:
                            self.data.vppf.create_router_interface_on_host(
                                router)
                elif m and m.group(1) == 'floatingip':
                    if action != 'delete':
                        floatingip_dict = json.loads(value)
                        if floatingip_dict['event'] == 'associate':
                            self.data.vppf.associate_floatingip(
                                floatingip_dict)
                        else:
                            self.data.vppf.disassociate_floatingip(
                                floatingip_dict)
                            self._del_key(self.data.router_key_space +
                                          '/floatingip/%s' % m.group(2))
                elif m and m.group(1) == 'router':
                    if action != 'delete':
                        router_id = m.group(2)
                        router = json.loads(value)
                        if router.get('delete', False):
                            # Delete an external gateway
                            (self.data.vppf.
                             delete_router_external_gateway_on_host(router))
                            self._del_key(self.data.router_key_space +
                                          '/router/%s' % router_id)
                        else:
                            # Add the external gateway
                            (self.data.vppf.
                             create_router_external_gateway_on_host(router))
                else:
                    LOG.warn('Unexpected key change in etcd router feedback,'
                             ' key %s' % key)

        # Check if the vpp router service plugin is enabled
        if 'vpp-router' in cfg.CONF.service_plugins:
            LOG.debug("Spawning router_watcher")
            self.pool.spawn(RouterWatcher(self.client_factory.client(),
                                          'router_watcher',
                                          self.router_key_space,
                                          heartbeat=self.AGENT_HEARTBEAT,
                                          data=self).watch_forever)

        class SecGroupWatcher(EtcdChangeWatcher):

            def do_tick(self):
                pass

            def removed(self, secgroup):
                LOG.debug("secgroup_watcher: deleting secgroup %s"
                          % secgroup)
                self.data.acl_delete(secgroup)

            def added(self, secgroup, value):
                # create or update a secgroup == add_replace vpp acl
                data = json.loads(value)
                LOG.debug("secgroup_watcher: add_replace secgroup %s"
                          % secgroup)
                self.data.acl_add_replace(secgroup, data)

                self.data.reconsider_port_secgroups()

        class GpeWatcher(EtcdChangeWatcher):

            def do_tick(self):
                pass

            def parse_key(self, gpe_key):
                m = re.match('([^/]+)' + '/([^/]+)' + '/([^/]+)', gpe_key)
                vni, hostname, mac = None, None, None
                if m:
                    vni = int(m.group(1))
                    hostname = m.group(2)
                    mac = m.group(3)
                return (vni, hostname, mac)

            def added(self, gpe_key, value):
                # gpe_key format is "vni/hostname/mac"
                vni, hostname, mac = self.parse_key(gpe_key)
                if (vni and hostname and mac and
                        self.data.is_valid_remote_map(vni, hostname)):
                    self.data.vppf.ensure_remote_gpe_mapping(
                        vni=vni,
                        mac=mac,
                        remote_ip=value)
                    LOG.debug("Current gpe map %s",
                              self.data.vppf.gpe_map)

            def removed(self, gpe_key):
                vni, hostname, mac = self.parse_key(gpe_key)
                if (vni and hostname and mac and
                        self.data.is_valid_remote_map(vni, hostname)):
                    self.data.vppf.delete_remote_gpe_mapping(
                        vni=vni,
                        mac=mac)

        if self.secgroup_enabled:
            LOG.debug("loading VppAcl map from acl tags for "
                      "performing secgroup_watcher lookups")
            self.vppf.populate_secgroup_acl_mappings()
            LOG.debug("Adding ingress/egress spoof filters "
                      "on host for secgroup_watcher spoof blocking")
            self.spoof_filter_on_host()
            LOG.debug("Spawning secgroup_watcher..")
            self.pool.spawn(SecGroupWatcher(self.client_factory.client(),
                                            'secgroup_watcher',
                                            self.secgroup_key_space,
                                            heartbeat=self.AGENT_HEARTBEAT,
                                            data=self).watch_forever)

        # The security group watcher will load the secgroups before
        # this point (before the thread is spawned) - that's helpful,
        # because it means that the ports will be immediately createable
        # as the secgroups are already available.
        LOG.debug("Spawning port_watcher")
        self.pool.spawn(PortWatcher(self.client_factory.client(),
                                    'port_watcher',
                                    self.port_key_space,
                                    heartbeat=self.AGENT_HEARTBEAT,
                                    data=self).watch_forever)
        # Spawn GPE watcher for vxlan tenant networks
        if 'vxlan' in cfg.CONF.ml2.type_drivers:
            LOG.debug("Spawning gpe_watcher")
            self.pool.spawn(GpeWatcher(self.client_factory.client(),
                                       'gpe_watcher',
                                       self.gpe_key_space,
                                       heartbeat=self.AGENT_HEARTBEAT,
                                       data=self).watch_forever)
        self.pool.waitall()


class BindNotifier(object):
    """A thread to return bind-complete notifications to the server.

    This notifies the completion of a bind by writing a state key with
    the details of VPP's config (the other end doesn't care about the
    content, only the key's presence, so this is purely a debugging
    issue) to etcd.

    """

    def __init__(self, client_factory, state_key_space):
        #  An infinite queue over which we receive notifications
        self.notifications = eventlet.queue.Queue()

        self.state_key_space = state_key_space

        self.etcd_client = client_factory.client()

    def add_notification(self, id, content):
        """Queue a notification for sending to Nova

        Nova watches a key's existence before sending out bind events.
        We set the key, and use the value to store debugging
        information.

        """

        self.notifications.put((id, content,))

    def run(self):
        while(True):
            try:
                ent = self.notifications.get()

                (port, props) = ent

                self.etcd_client.write(
                    self.state_key_space + '/%s' % port,
                    json.dumps(props))
            except Exception:
                # We must keep running, but we don't expect problems
                LOG.exception("exception in bind-notify thread")
                # If there are problems, retry the notification later.
                # There's no issue if we do this multiple times.
                self.add_notification(ent)
                pass


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
            except Exception:
                LOG.error("Could not parse physnet to interface mapping "
                          "check the format in the config file: "
                          "physnets = physnet1:<interface1>, "
                          "physnet2:<interface>"
                          )
                sys.exit(1)
            if len(v) > MAX_PHYSNET_LENGTH:
                LOG.error("Physnet '%s' is longer than %d characters.",
                          v, MAX_PHYSNET_LENGTH)
                sys.exit(1)
            physnets[k] = v

    # Convert to the minutes unit that VPP uses:
    # (we round *up*)
    mac_age_min = int((cfg.CONF.ml2_vpp.mac_age + 59) / 60)
    vppf = VPPForwarder(physnets,
                        mac_age=mac_age_min,
                        tap_wait_time=cfg.CONF.ml2_vpp.tap_wait_time,
                        vpp_cmd_queue_len=cfg.CONF.ml2_vpp.vpp_cmd_queue_len,
                        gpe_src_cidr=cfg.CONF.ml2_vpp.gpe_src_cidr,
                        vxlan_src_addr=cfg.CONF.ml2_vpp.vxlan_src_addr,
                        vxlan_bcast_addr=cfg.CONF.ml2_vpp.vxlan_bcast_addr,
                        vxlan_vrf=cfg.CONF.ml2_vpp.vxlan_vrf,
                        gpe_locators=cfg.CONF.ml2_vpp.gpe_locators,
                        )

    LOG.debug("Using etcd host:%s port:%s user:%s password:***",
              cfg.CONF.ml2_vpp.etcd_host,
              cfg.CONF.ml2_vpp.etcd_port,
              cfg.CONF.ml2_vpp.etcd_user)

    client_factory = nwvpp_utils.EtcdClientFactory(cfg.CONF.ml2_vpp)

    ops = EtcdListener(cfg.CONF.host, client_factory, vppf, physnets)

    ops.process_ops()

if __name__ == '__main__':
    main()
