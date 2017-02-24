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
from networking_vpp._i18n import _
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
from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

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

TAG_UPLINK_PREFIX = VPP_TAG('uplink:')
TAG_L2IFACE_PREFIX = VPP_TAG('port:')


def get_vhostuser_name(uuid):
    return os.path.join(cfg.CONF.ml2_vpp.vhost_user_dir, uuid)


def uplink_tag(net_type, seg_id):
    return TAG_UPLINK_PREFIX + '%s.%s' % (net_type, seg_id)


def decode_uplink_tag(tag):
    """Spot an uplink interface tag.

    Return (net_type, seg_id) or None if not an uplink tag
    """
    if tag is None:
        return None  # not tagged
    m = re.match('^' + TAG_UPLINK_PREFIX + '([^.]+)\.([^.]+)$', tag)
    return None if m is None else (m.group(1), m.group(2))


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


class UnsupportedInterfaceException(Exception):
    pass


class VPPForwarder(object):

    def __init__(self,
                 physnets,  # physnet_name: interface-name
                 mac_age,
                 tap_wait_time,
                 vpp_cmd_queue_len=None,
                 vxlan_src_addr=None,
                 vxlan_bcast_addr=None,
                 vxlan_vrf=None):
        self.vpp = vpp.VPPInterface(LOG, vpp_cmd_queue_len)

        self.physnets = physnets

        self.mac_age = mac_age

        # This is the address we'll use if we plan on broadcasting
        # vxlan packets
        self.vxlan_bcast_addr = vxlan_bcast_addr
        self.vxlan_src_addr = vxlan_src_addr
        self.vxlan_vrf = vxlan_vrf

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

    def get_if_for_physnet(self, physnet):
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
            if_upstream = ifidx

            LOG.debug('Adding upstream interface-idx:%s-%s to bridge '
                      'for flat networking', intf, if_upstream)

        elif net_type == 'vlan':
            LOG.debug('Adding upstream interface %s vlan %s '
                      'to bridge for vlan networking', intf, seg_id)
            # Besides the vlan sub-interface we need to also bring
            # up the primary uplink interface for Vlan networking
            self.vpp.ifup(ifidx)
            if_upstream = self.vpp.get_vlan_subif(intf, seg_id)
            if if_upstream is None:
                if_upstream = self.vpp.create_vlan_subif(ifidx, seg_id)

        # elif net_type == 'vxlan':
        #     # NB physnet not really used here
        #     if_upstream = \
        #         self.vpp.create_srcrep_vxlan_subif(self, self.vxlan_vrf,
        #                                            self.vxlan_src_addr,
        #                                            self.vxlan_bcast_addr,
        #                                            seg_id)
        else:
            raise Exception('network type %s not supported', net_type)

        # Mark this interface so that we can spot it on resync
        self.vpp.set_interface_tag(if_upstream,
                                   uplink_tag(net_type, seg_id))

        # Our bridge IDs have one upstream interface in so we simply use
        # that ID as their domain ID
        # This means we can find them on resync from the tagged interface
        self.ensure_interface_in_vpp_bridge(if_upstream, if_upstream)
        self.vpp.ifup(if_upstream)

        return {
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
        if net_br_idx not in self.vpp.get_ifaces_in_bridge_domains():
            self.vpp.create_bridge_domain(net_br_idx, self.mac_age)
        # Adding an interface to a bridge does nothing if it's
        # already in there
        self.vpp.add_to_bridge(net_br_idx, iface_idx)

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
            self.interfaces.pop(uuid)

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
        """Adds/Replaces the secgroup ACL within VPP

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

    def remove_acls_on_vpp_port(self, sw_if_index):
        """Removes all L3 and L2 ACLS on the vpp port

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
        spoof_acl = secgroups.get(COMMON_SPOOF_TAG)
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
                      "secgroups mapping %s", str(spoof_acl), secgroups)
            secgroups[COMMON_SPOOF_TAG] = spoof_acl
            LOG.debug("secgroup_watcher: current secgroup mapping: %s",
                      secgroups)
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
        self.etcd_helper.ensure_dir(LEADIN + '/state/%s/ports' % self.host)
        self.etcd_helper.ensure_dir(LEADIN + '/nodes/%s/ports' % self.host)
        # If the agent is started before q-svc, etcd watch fails as this
        # directory may not exist. Make sure it exists
        self.etcd_helper.ensure_dir(LEADIN + '/global/secgroups')
        self.pool = eventlet.GreenPool()
        self.secgroup_enabled = cfg.CONF.SECURITYGROUP.enable_security_group

        # key: if index in VPP; value: (ID, prop-dict) tuple
        self.iface_state = {}

        self.vppf.vhost_ready_callback = self._vhost_ready

    # The vppf bits

    def unbind(self, id):
        self.vppf.unbind_interface_on_host(id)

    def bind(self, id, binding_type, mac_address, physnet, network_type,
             segmentation_id):
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
        props = self.vppf.bind_interface_on_host(binding_type,
                                                 id,
                                                 mac_address,
                                                 physnet,
                                                 network_type,
                                                 segmentation_id)
        if props is None:
            # Problems with the binding
            return None

        # Store the binding information.  We put this into
        # etcd when the interface comes up to show that things
        # are ready and expose it to curious operators, who may
        # be able to debug with it.  This may not happen
        # immediately because the far end may not have connected.
        iface_idx = props['iface_idx']
        self.iface_state[iface_idx] = (id, props)

        if (binding_type != 'vhostuser' or
           self.vppf.vhostuser_linked_up(iface_idx)):
            # Handle the case where the interface has already been
            # notified as up, as we need both the up-notification
            # and bind information ito be ready before we tell Nova
            # For tap devices, the interface is now ready for a VM
            # regardless of whether we see the other end.

            # If it's not up now, we'll get a vhost_ready notification
            # later on.  We can't guarantee that vhost_ready notification
            # as we may be resyncing and it may have bound in the period
            # the agent was down.  This covers for that case.
            self._mark_up(iface_idx)

        return props

    def _vhost_ready(self, sw_if_index):
        if sw_if_index in self.iface_state:
            # This index is linked up, and we bound it
            # earlier.
            self._mark_up(sw_if_index)

    def _mark_up(self, sw_if_index):
        """Flag to Nova that an interface is connected.

        Nova watches a key's existence before sending out
        bind events.  We set the key, and use the value
        to store debugging information.

        This is a combination of 'we did our bit' and 'the other
        end connected'.  These can happen in either order; if
        we resync, we recheck our binding but the other end
        may have connected already.

        There is nothing wrong (other than a bit of inefficiency)
        in sending this multiple times; the watching driver may
        see the key write multiple times and will act accordingly.
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
        populate secgroups data structure
        secgroups = {secgroup_id : VppAcl(in_idx, out_idx)}
        """
        LOG.debug("secgroup_watcher: Populating secgroup to VPP ACL map..")
        # Clear existing secgroups to ACL map for sanity
        LOG.debug("secgroup_watcher: Clearing existing secgroups "
                  "to vpp-acl mappings")
        global secgroups
        secgroups = {}
        # Example of the acl_map data
        # acl_map: {'net-vpp.secgroup:<uuid>.from-vpp' : acl_idx
        #           'net-vpp.secgroup:<uuid>.to-vpp' : acl_idx,
        #           'net-vpp.common_spoof.from-vpp': acl_idx }
        acl_map = self.vppf.get_secgroup_acl_map()
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

            vpp_acl = secgroups.get(secgroup_id,
                                    VppAcl(0xffffffff, 0xffffffff))
            # secgroup_id will be missing first pass, and should be
            # completed on the second round through.
            if ingress:
                secgroups[secgroup_id] = vpp_acl._replace(
                    in_idx=acl_idx)
            else:
                secgroups[secgroup_id] = vpp_acl._replace(
                    out_idx=acl_idx)

            LOG.debug("secgroup_watcher: secgroup to VPP ACL mapping %s "
                      "constructed by reading "
                      "acl tags and building an acl_map %s"
                      % (secgroups, acl_map))

        if secgroups == {}:
            LOG.debug("secgroup_watcher: We have an empty secgroups "
                      "to acl mapping {}. Possible reason: vpp "
                      "may have been restarted on host.")

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
        self.vppf.set_acls_on_vpp_port(vpp_acls, sw_if_index)

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

        class PortWatcher(EtcdChangeWatcher):

            def do_tick(self):
                # The key that indicates to people that we're alive
                # (not that they care)
                # TODO(ijw): use refresh after the create to avoid the
                # notification
                self.etcd_client.write(LEADIN + '/state/%s/alive' %
                                       self.data.host,
                                       1, ttl=3 * self.heartbeat)

            def key_change(self, action, key, value):
                """Implement etcd state when it changes

                This implements the state in VPP and notes the key/value
                that VPP has implemented in self.implemented_state.
                """
                LOG.warn('Key change: %s', key)

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
                        # NB most things will not change on an update.
                        # TODO(ijw): go through the cases.
                        data = json.loads(value)
                        props = self.data.bind(port,
                                               data['binding_type'],
                                               data['mac_address'],
                                               data['physnet'],
                                               data['network_type'],
                                               data['segmentation_id'])
                        if props is None:
                            # The binding failed for some reason (typically
                            # a problem with physnet config); we don't quit,
                            # in case the rest of what we're doing is working,
                            # but we don't proceed any further.
                            # Nova will time out on the bind completion.
                            # An admin can also fix the config and this will
                            # cause binds to retry on startup resync.
                            # Until then, this etcd key will be ignored.
                            return

                        # If (security-groups and port_security)
                        # are enabled and it's a vhostuser port
                        # proceed to set L3/L2 ACLs, else skip security
                        if (self.data.secgroup_enabled
                                and data.get('port_security_enabled', True)
                                and data['binding_type'] == 'vhostuser'):
                            LOG.debug("port_watcher: known secgroup to acl "
                                      "mappings %s" % secgroups)
                            security_groups = data.get('security_groups', [])
                            LOG.debug("port_watcher:Setting secgroups %s "
                                      "on sw_if_index %s for port %s" %
                                      (security_groups,
                                       props['iface_idx'],
                                       port))
                            self.data.set_acls_on_port(
                                security_groups,
                                props['iface_idx'])
                            LOG.debug("port_watcher: setting secgroups "
                                      "%s on sw_if_index %s for port %s " %
                                      (security_groups,
                                       props['iface_idx'],
                                       port))
                            # Set Allowed address pairs and mac-spoof filter
                            aa_pairs = data.get('allowed_address_pairs', [])
                            LOG.debug("port_watcher: Setting allowed "
                                      "address pairs %s on port %s "
                                      "sw_if_index %s" %
                                      (aa_pairs,
                                       port,
                                       props['iface_idx']))
                            self.data.set_mac_ip_acl_on_port(
                                data['mac_address'],
                                data.get('fixed_ips'),
                                aa_pairs,
                                props['iface_idx'])
                            LOG.debug("port_watcher: setting allowed-addr-"
                                      "pairs %s on sw_if_index %s for "
                                      "port %s" %
                                      (aa_pairs,
                                       props['iface_idx'],
                                       port))
                        self.data.vppf.vpp.ifup(props['iface_idx'])
                        # Clear ACLs on vhostuser port if port_security
                        # is disabled
                        if (not data.get('port_security_enabled', True)
                                and data['binding_type'] == 'vhostuser'):
                            LOG.debug("Removing port_security on "
                                      "port %s", port)
                            self.data.vppf.remove_acls_on_vpp_port(
                                props['iface_idx'])

                else:
                    LOG.warning('Unexpected key change in etcd '
                                'port feedback, key %s', key)

        class SecGroupWatcher(EtcdChangeWatcher):

            def do_tick(self):
                pass

            def key_change(self, action, key, value):
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

        # The security group watcher will load the secgroups before
        # this point (before the thread is spawned) - that's helpful,
        # because it means that the ports will be immediately createable
        # as the secgroups are already available.
        LOG.debug("Spawning port_watcher")
        self.pool.spawn(PortWatcher(self.etcd_client, 'port_watcher',
                                    self.port_key_space,
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
                        tap_wait_time=cfg.CONF.ml2_vpp.tap_wait_time,
                        vpp_cmd_queue_len=cfg.CONF.ml2_vpp.vpp_cmd_queue_len,
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
