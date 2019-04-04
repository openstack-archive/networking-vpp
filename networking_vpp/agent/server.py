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

from __future__ import absolute_import
# eventlet must be monkey patched early or we confuse urllib3.
import eventlet

# We actually need to co-operate with a threaded callback in VPP, so
# don't monkey patch the thread operations.
eventlet.monkey_patch(thread=False)

import binascii
from collections import defaultdict
from collections import namedtuple
import etcd
import eventlet.semaphore
import ipaddress
import os
import re
import shlex
import six
import sys
import time

from networking_vpp._i18n import _
from networking_vpp.agent import gpe
from networking_vpp.agent import vpp
from networking_vpp import compat
from networking_vpp.compat import n_const
from networking_vpp.compat import net_utils
from networking_vpp import config_opts
from networking_vpp import constants as nvpp_const
from networking_vpp import etcdutils
from networking_vpp.ext_manager import ExtensionManager
from networking_vpp.extension import VPPAgentExtensionBase
from networking_vpp.mech_vpp import SecurityGroup
from networking_vpp.mech_vpp import SecurityGroupRule
from networking_vpp.utils import device_monitor
from networking_vpp.utils import file_monitor
from networking_vpp import version

from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
try:
    # TODO(ijw): TEMPORARY, better fix coming that reverses this
    from neutron.plugins.ml2 import config
    assert config
except ImportError:
    from neutron.conf.plugins.ml2 import config
    config.register_ml2_plugin_opts()
from oslo_config import cfg
from oslo_log import log as logging
from oslo_privsep import priv_context
from oslo_reports import guru_meditation_report as gmr
from oslo_reports import opts as gmr_opts
from oslo_serialization import jsonutils


TYPE_GPE = nvpp_const.TYPE_GPE

LOG = logging.getLogger(__name__)

# A model of a bi-directional VPP ACL corresponding to a secgroup
VppAcl = namedtuple('VppAcl', ['in_idx', 'out_idx'])

# TODO(najoy) Expose the below as a config option
# Enable stateful reflexive ACLs in VPP which adds automatic reverse rules
# When False, reverse rules are added by the vpp-agent and
# VPP does not maintain any session states
reflexive_acls = True

# Apply monkey patch if necessary
compat.monkey_patch()

# We use eventlet for everything but threads. Here, we need an eventlet-based
# locking mechanism, so we call out eventlet specifically rather than using
# threading.Semaphore.
#
# Our own, strictly eventlet, locking:
_semaphores = defaultdict(eventlet.semaphore.Semaphore)


def get_root_helper(conf):
    """Root helper configured for privilege separation"""
    return conf.AGENT.root_helper


def setup_privsep():
    """Use root helper (if present) to execute privileged commands"""
    priv_context.init(root_helper=shlex.split(get_root_helper(cfg.CONF)))


def eventlet_lock(name):
    sema = _semaphores[name]

    def eventlet_lock_decorator(func):
        def func_wrap(*args, **kwargs):
            LOG.debug("Acquiring lock '%s' before executing %s" %
                      (name, func.__name__))
            with sema:
                LOG.debug("Acquired lock '%s' before executing %s" %
                          (name, func.__name__))
                return func(*args, **kwargs)
        return func_wrap
    return eventlet_lock_decorator


# TODO(onong): move to common file in phase 2
def ipnet(ip):
    return ipaddress.ip_network(six.text_type(ip))


def ipaddr(ip):
    return ipaddress.ip_address(six.text_type(ip))


def ipint(ip):
    return ipaddress.ip_interface(six.text_type(ip))

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


def default_if_none(x, default):
    return default if x is None else x

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
    m = re.match('^' + TAG_UPLINK_PREFIX + r'([^.]+)\.([^.]+)\.([^.]+)$', tag)
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
    m = re.match('^' + SECGROUP_TAG + '(' + n_const.UUID_PATTERN + r')\.(.*)$',
                 tag)
    if m:
        secgroup_id = m.group(1)
        dirmark = m.group(2)
        is_vm_ingress = dirmark == VPP_TO_VM_MARK
        return secgroup_id, is_vm_ingress

    return None, None


class UnsupportedInterfaceException(Exception):
    """Used when ML2 has tried to ask for a weird binding type."""
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
                 vpp_cmd_queue_len=None,
                 read_timeout=None):
        self.vpp = vpp.VPPInterface(LOG, vpp_cmd_queue_len, read_timeout)

        self.physnets = physnets

        self.mac_age = mac_age

        # a Mapping of security groups to VPP ACLs
        self.secgroups = {}  # secgroup_uuid: VppAcl(ingress_idx, egress_idx)

        # Security group UUID to the set of associated port UUIDs
        self.remote_group_ports = defaultdict(set)
        # Port UUID to its set of IP addresses
        self.port_ips = defaultdict(set)
        # Remote-group UUID to the set to security-groups that uses it
        self.remote_group_secgroups = defaultdict(set)

        # ACLs we ought to delete
        self.deferred_delete_secgroups = set()

        # Enable the GPE forwarder programming, if required
        if TYPE_GPE in cfg.CONF.ml2.type_drivers:
            self.gpe = gpe.GPEForwarder(self)
        else:
            self.gpe = None

        self.networks = {}      # (physnet, type, ID): datastruct
        self.interfaces = {}    # uuid: if idx
        self.router_interfaces = {}  # router_port_uuid: {}
        self.router_external_interfaces = {}  # router external interfaces
        self.floating_ips = {}  # floating_ip_uuid: {}
        if cfg.CONF.ml2_vpp.enable_l3_ha:
            # Router BVI (loopback) interface states for L3-HA
            self.router_interface_states = {}  # {idx: state} 1 = UP, 0 = DOWN
            # VPP Router state variable is updated by the RouterWatcher
            # The default router state is the BACKUP.
            # If this node should be the master it will be told soon enough,
            # and this will prevent us from having two masters on any restart.
            self.router_state = False  # True = Master; False = Backup
        # mac_ip acls do not support atomic replacement.
        # Here we create a mapping of sw_if_index to VPP ACL indices
        # so we can easily lookup the ACLs associated with the interface idx
        # sw_if_index: {"l34": [l34_acl_indxs], "l23": l23_acl_index }
        self.port_vpp_acls = defaultdict(dict)

        # key: OpenStack port UUID; present when vhost-user is
        # connected and removed when we delete things.  May accumulate
        # any other VPP interfaces too, but that's harmless.
        self.port_connected = set()
        self.vhost_ready_callback = None
        eventlet.spawn_n(self.vhost_notify_thread)

        # Device monitor to ensure the tap interfaces are plugged into the
        # right Linux brdige
        self.device_monitor = device_monitor.DeviceMonitor()
        self.device_monitor.on_add(self._consider_external_device)
        # The worker will be in endless loop, so don't care the return value
        eventlet.spawn_n(self.device_monitor.run)

        # Start Vhostsocket filemonitor to bind sockets as soon as they appear.
        self.filemonitor = file_monitor.FileMonitor(
            watch_pattern=n_const.UUID_PATTERN,
            watch_dir=cfg.CONF.ml2_vpp.vhost_user_dir)
        # Register to handle ON_CREATE event.
        self.filemonitor.register_on_add_cb(
            self.ensure_interface_for_vhost_socket_binding)
        # Register to handle ON_DELETE event.
        # We are expecting the port unbinding call flow to clean up vhost
        # sockets, hence ignoring delete events on vhost file handle.
        self.filemonitor.register_on_del_cb(lambda *args: None)
        # Finally start the file monitor.
        eventlet.spawn_n(self.filemonitor.run)

    ########################################
    # Port resyncing on restart

    def fix_physnets(self, physnets):
        """Fix or remove networks where uplinks have changed in config

        - fixes uplink interfaces from VPP where they've changed in
          config or where the config didn't fully get pushed
          to VPPFowarder
        - deletes interfaces and networks from VPP where the
          the physical network is no longer configured
        - evicts ports from bridges with no network
        """

        # One uplink per network
        uplink_ports_found = []

        # One physnet can serve multiple uplinks
        physnet_ports_found = {}

        for f in self.vpp.get_interfaces():

            # Find uplink ports on OpenStack networks
            uplink_data = decode_uplink_tag(f['tag'])
            if uplink_data is not None:
                uplink_physnet, net_type, seg_id = uplink_data
                uplink_ports_found.append([
                    uplink_physnet, net_type, seg_id,
                    f['sw_if_idx'],
                    f['sw_if_idx'] if f['sup_sw_if_idx'] is None
                    else f['sup_sw_if_idx']])

            # Find physical network ports
            physnet_name = decode_physnet_if_tag(f['tag'])
            if physnet_name is not None:
                physnet_ports_found[physnet_name] = f['sw_if_idx']

        # Find physnets we intend according to the config
        configured_physnet_interfaces = {}
        for name, if_name in physnets.items():
            # Can be 'None', that's fine as it won't match anything later
            configured_physnet_interfaces[name] = \
                self.vpp.get_ifidx_by_name(if_name)

        LOG.debug('Configured physnets %s',
                  ', '.join(sorted(configured_physnet_interfaces.keys())))

        for uplink_physnet, net_type, seg_id, sw_if_idx, sup_sw_if_idx \
                in uplink_ports_found:
            # Delete networks with a physnet whose config changed
            if (uplink_physnet not in configured_physnet_interfaces
                    or (sup_sw_if_idx !=
                        configured_physnet_interfaces[uplink_physnet])):
                LOG.warning('Deleting outdated network in VPP: net type '
                            '%(type)s physnet %(physnet)s seg id %(seg)s, '
                            'physnet if %(physif)d uplink %(uplinkif)d',
                            {'type': net_type,
                             'physnet': uplink_physnet,
                             'seg': str(seg_id),
                             'physif': sup_sw_if_idx,
                             'uplinkif': sw_if_idx})
                if uplink_physnet not in configured_physnet_interfaces:
                    LOG.warning('This physnet is no longer in the config')
                else:
                    LOG.warning(
                        'This physnet now uses interface '
                        '%(idx)d (%(physnet_name)s)',
                        {'idx': configured_physnet_interfaces[uplink_physnet],
                         'physnet_name': physnets[uplink_physnet]})
                # This will remove ports from bridges, which means
                # that they may be rebound back into networks later
                # or may be deleted if no longer used.
                self.delete_network_bridge_on_host(net_type,
                                                   sw_if_idx,
                                                   sw_if_idx)

        for name, if_idx in physnet_ports_found.items():
            if configured_physnet_interfaces.get(name, None) != if_idx:
                # This configuration has changed.
                # Untag the original physnet interface, which is no
                # longer used as a physnet
                LOG.warning('Removing old physnet from VPP: '
                            'physnet %(physnet_name)s interface %(idx)s',
                            {'physnet_name': name,
                             'idx': str(if_idx)})

                # In case there was a flat network, make sure the flat
                # network bridge no longer exists
                self.delete_network_bridge_on_host('flat', if_idx, if_idx)

                self.vpp.set_interface_tag(if_idx, None)

        # The remaining networks (with uplinks and bridge domains) are
        # functional, and idempotent binding will do nothing to
        # interfaces in the right bridges.  It will fix those in the
        # wrong bridges.
        # Dead bridges have been deleted and binding
        # will find a new home for the interfaces that still exist.

    def find_bound_ports(self):
        """Assuming no local data, find bound ports in VPP

        This analyses the tags to identify ports in VPP that
        have been bound by this process before it restarted.
        """

        bound_ports = set()

        for f in self.vpp.get_interfaces():
            # Find downlink ports
            port_id = decode_port_tag(f['tag'])
            if port_id is not None:
                bound_ports.add(port_id)

        return bound_ports

    ########################################

    def vhost_notify_thread(self):
        """Find vhostuser connections with an attached VM

        The moment of VM attachment is useful, as it's one of the
        preconditions for notifying Nova a socket is ready.  Watching
        the vhostuser data inside VPP has a performance impact on
        forwarding, so instead we watch the kernel's idea of which
        vhostuser connections are properly opened.

        Having two open sockets is 99% ready - technically, the interface
        is ready when VPP has mapped its memory, but these two events are
        nearly contemporaenous, so this is good enough.
        """
        dirname = cfg.CONF.ml2_vpp.vhost_user_dir
        # We need dirname to have precisely one trailing slash.
        dirname = dirname.rstrip('/') + '/'

        while True:
            opens = defaultdict(int)

            with open('/proc/net/unix') as file:
                # Track unix sockets in vhost directory that are opened more
                # than once
                for f in file:
                    # Problems with files with spaces in, though
                    _, file = f.rsplit(' ', 1)
                    if file.startswith(dirname):
                        file = file[len(dirname):].rstrip("\n")
                        opens[file] = opens[file] + 1

            # Report on any sockets that are open exactly twice (VPP + KVM)
            # (note list clone so that we can delete entries)
            for f in list(opens.keys()):
                if opens[f] != 2:
                    del opens[f]

            opens = set(opens.keys())
            open_notifications = opens - self.port_connected
            # .. we don't have to notify the port drops, that's fine

            # Update this *before* making callbacks so that this register is up
            # to date
            self.port_connected = opens
            if self.vhost_ready_callback:
                for uuid in open_notifications:
                    self.vhost_ready_callback(uuid)

            eventlet.sleep(1)

    def vhostuser_linked_up(self, uuid):
        return uuid in self.port_connected

    def vhostuser_unlink(self, uuid):
        self.port_connected.discard(uuid)

    ########################################

    def ifup(self, ifidx):
        """Proxy for VPP's ifup."""
        self.vpp.ifup(ifidx)

    ########################################

    def get_if_for_physnet(self, physnet):
        """Find (and mark used) the interface for a physnet"""
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

        # On resync, we will be recreating our datastructure.
        # On general activity we skip to the chase.
        if (physnet, net_type, seg_id) not in self.networks:
            net = self.ensure_network_in_vpp(physnet, net_type, seg_id)
            if net:
                self.networks[(physnet, net_type, seg_id)] = net

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

        elif net_type == TYPE_GPE and self.gpe is not None:
            # GPE bridges have no uplink interface at all.
            # We link the bridge directly to the GPE code.

            self.gpe.ensure_gpe_link()
            bridge_idx = self.gpe.bridge_idx_for_segment(seg_id)
            self.ensure_bridge_domain_in_vpp(bridge_idx)
            self.gpe.ensure_gpe_vni_to_bridge_mapping(seg_id, bridge_idx)

            # We attach the bridge to GPE without use of an uplink interface
            # as we affect forwarding in the bridge.
            if_uplink = None

        else:
            raise Exception(_('network type %s not supported'), net_type)

        rv = {
            'physnet': physnet,
            'if_physnet': intf,
            'bridge_domain_id': bridge_idx,
            'network_type': net_type,
            'segmentation_id': seg_id,
        }

        if if_uplink is not None:
            self.vpp.ifup(if_uplink)
            rv['if_uplink_idx'] = if_uplink

        return rv

    def delete_network_on_host(self, physnet, net_type, seg_id=None):
        net = self.networks.get((physnet, net_type, seg_id,), None)
        if net is not None:
            bridge_domain_id = net['bridge_domain_id']
            uplink_if_idx = net.get('if_uplink_idx', None)

            if net['network_type'] == TYPE_GPE and self.gpe is not None:
                # TODO(ijw): this needs reconsidering for resync
                # network cleanup cases - it won't be called if it
                # lives here - but for now, these rely on local
                # caches of GPE data we programmed.

                LOG.debug("Deleting vni %s from GPE map", seg_id)
                self.gpe.delete_vni_from_gpe_map(seg_id)
                # Delete all remote mappings corresponding to this VNI
                self.gpe.clear_remote_gpe_mappings(seg_id)
                # Delete VNI to bridge domain mapping
                self.gpe.delete_gpe_vni_to_bridge_mapping(seg_id,
                                                          bridge_domain_id
                                                          )

            self.delete_network_bridge_on_host(net_type, bridge_domain_id,
                                               uplink_if_idx)

            # We may not know of this network (if we're dealing with
            # resync on restart, for instance); delete a record
            # if one exists.
            self.networks.pop((physnet, net_type, seg_id,))
        else:
            LOG.warning("Delete Network: network is unknown to agent")

    def delete_network_bridge_on_host(self, net_type, bridge_domain_id,
                                      uplink_if_idx):
        """Delete a bridge corresponding to a network from VPP

        Usable on restart - uses nothing but the data in VPP.
        """
        if bridge_domain_id in self.vpp.get_bridge_domains():
            # If there are ports still in this network, disable them
            # They may be deleted later (if at startup) or they may
            # be rebound to another bridge domain
            if_idxes = self.vpp.get_ifaces_in_bridge_domain(bridge_domain_id)

            # When this bridge domain is for an OpenStack flat network, the
            # uplink interface may be a physical interface, i.e. not VLAN-based
            # sub-interfaces. In this case, we will not bring down the uplink
            # interface, and always leave it UP.
            if_idxes_without_uplink = \
                [i for i in if_idxes if i != uplink_if_idx]

            # At startup, this is downing the interfaces in a bridge that
            # is no longer required.  However, in free running, this
            # should never find interfaces at all - they should all have
            # been unbound before the deletion.  (If it does find them,
            # the removal of interfaces is probably the best thing we can
            # do, but they may not stay down if it races with the binding
            # code.)
            self.vpp.ifdown(*if_idxes_without_uplink)
            self.vpp.delete_from_bridge(*if_idxes)
            self.vpp.delete_bridge_domain(bridge_domain_id)

        # The physnet is gone so no point in keeping the vlan sub-interface
        # TODO(onong): VxLAN
        if net_type == 'vlan':
            if uplink_if_idx is not None:
                self.vpp.delete_vlan_subif(uplink_if_idx)

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

    def ensure_kernel_bridge(self, bridge_name):
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
            bridge_device.setfd(0)
            bridge_device.disable_stp()
            bridge_device.disable_ipv6()
            bridge_device.link.set_up()
        else:
            bridge_device = bridge_lib.BridgeDevice(bridge_name)
        return bridge_device

        # TODO(ijw): should be checking this all succeeded

    # end theft
    ########################################
    def _consider_external_device(self, dev_name):
        """See if we need to take action when a net device is created

        This function will be called as a callback when a new interface is
        created in Linux kernel. We will filter for tap interfaces created by
        OpenStack, and those will be added to the bridges that we create on the
        Neutron side of things.
        """
        match = re.search(r'tap[0-9a-f]{8}-[0-9a-f]{2}', dev_name)
        if not match:
            return

        # TODO(ijw) will act upon other mechanism drivers' taps

        port_id = dev_name[3:]
        bridge_name = "br-%s" % port_id
        self.ensure_tap_in_bridge(dev_name, bridge_name)

    def ensure_tap_in_bridge(self, tap_name, bridge_name):
        """Add a TAP device to a bridge

        Defend against this having been done already (common on restart)
        and this missing a requirement (common when plugging external
        tap interfaces).
        """

        bridge = bridge_lib.BridgeDevice(bridge_name)
        bridge.set_log_fail_as_error(False)
        if bridge.exists() and ip_lib.device_exists(tap_name) \
           and not bridge.owns_interface(tap_name):
            try:
                bridge.addif(tap_name)
            except Exception as ex:
                # External TAP interfaces created by DHCP or L3 agent will be
                # added to corresponding Linux Bridge by vpp-agent to talk to
                # VPP. During a regular port binding process, there are two
                # code paths calling this function for adding the interface to
                # the Linux Bridge, which may potentially cause a race
                # condition and a non-harmful traceback in the log.

                # The fix will eliminate the non-harmful traceback in the log.
                match = re.search(r"Stderr\: device (vpp|tap)[0-9a-f]{8}-"
                                  "[0-9a-f]{2} is already a member of a "
                                  "bridge; can't enslave it to bridge br-"
                                  r'[0-9a-f]{8}-[0-9a-f]{2}\.', ex.message)
                if not match:
                    LOG.exception("Can't add interface %s to bridge %s: %s" %
                                  (tap_name, bridge_name, ex.message))

    def _ensure_kernelside_tap(self, bridge_name, tap_name, int_tap_name):
        # This is the kernel-side config (and we should not assume
        # that, just because the interface exists in VPP, it has
        # been done previously - the crash could occur in the
        # middle of the process)
        # Running it twice is harmless.  Never running it is
        # problematic.

        # TODO(ijw): someone somewhere ought to be sorting
        # the MTUs out
        self.ensure_kernel_bridge(bridge_name)

        # This is the device that we just created with VPP
        self.ensure_tap_in_bridge(int_tap_name, bridge_name)

        # This is the external TAP device that will be
        # created by Nova or an agent, say the DHCP agent,
        # later in time.
        self.ensure_tap_in_bridge(tap_name, bridge_name)

    # This is called by the (eventlet) inotify functions and the (eventlet)
    # etcd functionality, and thus needs an eventlet-based lock. We've found
    # oslo_concurrency thinks that, because threading is unpatched, a threading
    # lock is required, but this ends badly.
    @eventlet_lock('ensure-interface-lock')
    def ensure_interface_on_host(self, if_type, uuid, mac=None):
        """Create or update vpp interface on host based on if_type.

        Depending on the if_type (maketap, plugtap or vhostuser) call vpp papi
        to do vpp side of the plumbing. This will change depending on the
        if_type. The interfaces are tagged saved in the internal dict for easy
        retrieval.

        The call is idempotent if the uuid and its associated
        interface is already present.

        :return: dict indexed on uuid
        """

        if uuid in self.interfaces:
            # It's definitely there, we made it ourselves
            pass
        else:
            # TODO(ijw): it may exist, but we may need to create it
            # - and what exists may be wrong so we may have to
            # recreate it
            # TODO(ijw): idempotency

            # Unfortunately call_vpp() expects a mac and we need to pass one.
            # We will create a random mac if none is passed. We are setting
            # base_mac from neutron, assuming neutron is the sole consumer of
            # code at the moment. This is an assumption which might need a todo

            if mac is None:
                mac = net_utils.get_random_mac(
                    cfg.CONF.ml2_vpp.vpp_base_mac.split(':'))

            LOG.debug('Creating port %s as type %s with mac %s',
                      uuid, if_type, mac)

            # Deal with the naming conventions of interfaces

            # TODO(ijw): naming not obviously consistent with
            # Neutron's naming
            tap_name = get_tap_name(uuid)

            if if_type == 'tap':
                bridge_name = get_bridge_name(uuid)
                int_tap_name = get_vpptap_name(uuid)

                props = {'bridge_name': bridge_name,
                         'ext_tap_name': tap_name,
                         'int_tap_name': int_tap_name}
            elif if_type == 'vhostuser':
                path = get_vhostuser_name(uuid)
                props = {'path': path}
            else:
                raise UnsupportedInterfaceException()

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

                if if_type == 'tap':
                    iface_idx = self.vpp.create_tap(int_tap_name, mac, tag)
                elif if_type == 'vhostuser':
                    iface_idx = self.vpp.create_vhostuser(path, mac, tag)

            if if_type == 'tap':
                # Plugtap interfaces belong in a kernel bridge, and we need
                # to monitor for the other side attaching.
                self._ensure_kernelside_tap(bridge_name,
                                            tap_name,
                                            int_tap_name)

            props['iface_idx'] = iface_idx
            self.interfaces[uuid] = props
        return self.interfaces[uuid]

    def ensure_interface_for_vhost_socket_binding(self, name):
        """Ensure vpp interface for imminent vhost socket binding.

        Somebody has dropped a file in the vhost_socket_directory which matched
        our watch pattern (Neutron port uuid). We are expecting an imminent
        vhost socket binding (from presumably Nova), so lets get ahead of the
        curve and create a vhost socket for it.

        Inteface name is the vhost socket file name and since we don't know
        the mac, let vhost interface create function make one.

        """

        LOG.debug("Calling VPP interface creation on vhost socket with props "
                  "vif_type: %s , uuid: %s ", 'vhostuser', name)
        self.ensure_interface_on_host('vhostuser', uuid=name, mac=None)

    def ensure_interface_in_vpp_bridge(self, net_br_idx, iface_idx):
        """Idempotently ensure that a bridge contains an interface

        The interface must exist, but we ensure the bridge exists and
        that the interface is in it
        """
        self.ensure_bridge_domain_in_vpp(net_br_idx)

        # Adding an interface to a bridge does nothing if it's
        # already in there, and moves it if it's in another
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
            # For resyncs, the port exists but it's not in a bridge domain
            # and is down, which is the best we can offer.
            return None
        if net_type == TYPE_GPE and self.gpe is None:
            LOG.error('port bind - GPE is not enabled')
            return None

        net_br_idx = net_data['bridge_domain_id']
        props = self.ensure_interface_on_host(if_type, uuid, mac)
        iface_idx = props['iface_idx']
        self.ensure_interface_in_vpp_bridge(net_br_idx, iface_idx)
        # Ensure local mac to VNI mapping for GPE
        if net_type == TYPE_GPE:
            mac = props['mac']
            LOG.debug('Adding local GPE mapping for seg_id:%s and mac:%s',
                      seg_id, mac)
            self.gpe.add_local_gpe_mapping(seg_id, mac)

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
            net = props.get('net_data')
            self.clean_interface_from_vpp(uuid, props)
            # Delete the port ip address from remote_group_id list
            self.port_ips.pop(uuid, None)

            if net is not None:
                # Check if this is the last interface on host, safe if this
                # interface is incompletely bound
                for interface in self.interfaces.values():
                    if net == interface.get('net_data'):
                        # safe if the other interface is not bound
                        break
                else:
                    # Network is not used on this host, delete it
                    self.delete_network_on_host(net['physnet'],
                                                net['network_type'],
                                                net['segmentation_id'])

    def bind_subport_on_host(self, parent_port, subport_data):
        """Bind the subport of a bound parent vhostuser port."""
        # We ensure parent port binding before calling this method.
        subport_uuid = subport_data['port_id']
        subport_seg_id = subport_data['segmentation_id']

        # parent vhostuser intf
        parent_props = self.interfaces[parent_port]
        parent_if_idx = parent_props['iface_idx']
        # Ensure that the uplink and the BD's are setup
        physnet = subport_data['physnet']
        uplink_seg_type = subport_data['uplink_seg_type']
        uplink_seg_id = subport_data['uplink_seg_id']
        LOG.debug('trunk: ensuring subport network on host '
                  'physnet %s, uplink_seg_type %s, uplink_seg_id %s',
                  physnet, uplink_seg_type, uplink_seg_id)
        # Ensure an uplink for the subport
        # Use the uplink physnet, uplink_seg_id & seg_type
        net_data = self.ensure_network_on_host(physnet,
                                               uplink_seg_type,
                                               uplink_seg_id)
        if net_data is None:
            LOG.error('trunk sub-port binding is not possible as the '
                      'physnet could not be configured for subport')
            return None

        # fetch if the subport interface already in vpp
        subport_tag = port_tag(subport_uuid)
        subport_if_idx = self.vpp.get_ifidx_by_tag(subport_tag)
        net_br_idx = net_data['bridge_domain_id']
        if subport_if_idx is not None:
            # It's already there and we created it
            LOG.debug('Recovering existing trunk subport %s in VPP',
                      subport_uuid)
            # Ensure that the recovered subport is in vpp bridge
            self.ensure_interface_in_vpp_bridge(net_br_idx, subport_if_idx)
        else:
            # create subport vhostuser intf and ensure it's in vpp bridge
            LOG.debug('trunk: ensuring subport interface on host '
                      'parent_if_idx %s, seg_id %s', parent_if_idx,
                      subport_seg_id)
            subport_if_idx = self.vpp.create_vlan_subif(parent_if_idx,
                                                        subport_seg_id)
            self.ensure_interface_in_vpp_bridge(net_br_idx, subport_if_idx)
            # set subport tag, so we can find it during resyncs
            self.vpp.set_interface_tag(subport_if_idx, subport_tag)
            LOG.debug("Bound subport in vpp with sw_idx: %s on BD: %s ",
                      subport_if_idx, net_br_idx)
        # Add subport props to interfaces along with parent port uuid
        self.interfaces[subport_uuid] = {'iface_idx': subport_if_idx,
                                         'net_data': net_data,
                                         'mac': parent_props['mac'],
                                         'bind_type': 'vhostuser',
                                         'path': parent_props['path'],
                                         'parent_uuid': parent_port
                                         }

        if 'trunk' not in parent_props:
            LOG.debug('Setting trunk attr value in parent port props for '
                      'subport %s', subport_uuid)
            parent_props['trunk'] = set([subport_uuid])
        else:
            LOG.debug('Adding subport to trunk parent props for subport %s ',
                      subport_uuid)
            parent_props['trunk'].add(subport_uuid)
        return self.interfaces[subport_uuid]

    def unbind_subport_on_host(self, subport):
        """Unbind the vhostuser subport in VPP."""
        if subport not in self.interfaces:
            LOG.debug('unknown subport %s unbinding request - ignored',
                      subport)
        else:
            LOG.debug("Unbinding subport %s on host", subport)
            parent_port = self.interfaces[subport]['parent_uuid']
            LOG.debug("Parent port id of subport %s is %s",
                      subport, parent_port)
            self.unbind_interface_on_host(subport)
            self.interfaces[parent_port]['trunk'].remove(subport)

    def clean_interface_from_vpp(self, uuid, props):
        # Don't unbind a trunk port with subports
        if 'trunk' in props and len(props['trunk']) > 0:
            LOG.debug('Waiting for subports %s to be unbound before '
                      'unbinding trunk port %s', props, uuid)
            return
        iface_idx = props['iface_idx']

        LOG.debug('unbinding port %s, recorded as type %s',
                  uuid, props['bind_type'])

        # We no longer need this interface.  Specifically if it's
        # a vhostuser interface it's annoying to have it around
        # because the VM's memory (hugepages) will not be
        # released.  So, here, we destroy it.

        # GPE code in VPP does not clean up its data structures
        # properly if the port
        # is deleted from the bridge without first removing the
        # local GPE eid mapping. So remove local mapping,
        # if we are bound using GPE

        if props['net_data']['network_type'] == TYPE_GPE \
                and self.gpe is not None:
            mac = props['mac']
            seg_id = props['net_data']['segmentation_id']
            self.gpe.delete_local_gpe_mapping(seg_id, mac)

        if props['bind_type'] == 'vhostuser':
            # remove port from bridge (sets to l3 mode) prior to deletion
            self.vpp.delete_from_bridge(iface_idx)
            # If it is a subport of a trunk port then delete the corresponding
            # vlan sub-interface. Otherwise it is a parent port or a normal
            # vhostuser port and we delete the vhostuser interface itself.
            if 'parent_uuid' not in props:
                self.vpp.delete_vhostuser(iface_idx)
            else:
                self.vpp.delete_vlan_subif(iface_idx)
            # Delete port from vpp_acl map if present
            if iface_idx in self.port_vpp_acls:
                del self.port_vpp_acls[iface_idx]
            # This interface is no longer connected if it's deleted
            # RACE, as we may call unbind BEFORE the vhost user
            # interface is notified as connected to qemu
            self.vhostuser_unlink(uuid)
        elif props['bind_type'] == 'tap':
            # remove port from bridge (sets to l3 mode) prior to deletion
            self.vpp.delete_from_bridge(iface_idx)
            self.vpp.delete_tap(iface_idx)

            bridge_name = get_bridge_name(uuid)

            class FailableBridgeDevice(bridge_lib.BridgeDevice):
                # For us, we expect failing commands and want them ignored.
                def _brctl(self, cmd):
                    cmd = ['brctl'] + cmd
                    ip_wrapper = ip_lib.IPWrapper(self.namespace)
                    return ip_wrapper.netns.execute(
                        cmd,
                        check_exit_code=False,
                        log_fail_as_error=False,
                        run_as_root=True
                    )
            bridge = FailableBridgeDevice(bridge_name)
            if bridge.exists():
                # These may fail, don't care much
                if bridge.owns_interface(props['int_tap_name']):
                    bridge.delif(props['int_tap_name'])
                if bridge.owns_interface(props['ext_tap_name']):
                    bridge.delif(props['ext_tap_name'])
                bridge.link.set_down()
                bridge.delbr()
        else:
            LOG.error('Unknown port type %s during unbind',
                      props['bind_type'])
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
            elif r.port_max == -1:  # All ICMP codes for an ICMP Type
                acl_rule['srcport_or_icmptype_first'] = r.port_min
                acl_rule['srcport_or_icmptype_last'] = r.port_min
                acl_rule['dstport_or_icmpcode_first'] = 0
                acl_rule['dstport_or_icmpcode_last'] = 255
            else:  # port_min == ICMP Type and port_max == ICMP Code
                acl_rule['srcport_or_icmptype_first'] = r.port_min
                acl_rule['srcport_or_icmptype_last'] = r.port_min
                acl_rule['dstport_or_icmpcode_first'] = r.port_max
                acl_rule['dstport_or_icmpcode_last'] = r.port_max
        # Handle TCP/UDP protocols
        elif r.protocol in [6, 17]:
            acl_rule['dstport_or_icmpcode_first'] = \
                default_if_none(r.port_min, 0)
            acl_rule['dstport_or_icmpcode_last'] = \
                default_if_none(r.port_max, 65535)
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
                LOG.error("Invalid rule %s to be reversed", r)
                return {}
            # Swap port range values
            acl_rule['srcport_or_icmptype_first'] = \
                r['dstport_or_icmpcode_first']
            acl_rule['srcport_or_icmptype_last'] = \
                r['dstport_or_icmpcode_last']
            acl_rule['dstport_or_icmpcode_first'] = \
                r['srcport_or_icmptype_first']
            acl_rule['dstport_or_icmpcode_last'] = \
                r['srcport_or_icmptype_last']
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

        in_acl_rules, out_acl_rules = (
            [self._to_acl_rule(r, 0) for r in secgroup.ingress_rules],
            [self._to_acl_rule(r, 1) for r in secgroup.egress_rules])

        # If not reflexive_acls create return rules for ingress and egress
        # IPv4/IPv6 tcp/udp traffic
        # Exclude ICMP
        if not reflexive_acls:
            in_acl_return_rules, out_acl_return_rules = (
                [self._reverse_rule(r) for r in in_acl_rules
                    if r['proto'] in [6, 17, 0]],
                [self._reverse_rule(r) for r in out_acl_rules
                    if r['proto'] in [6, 17, 0]]
                )
            in_acl_rules = in_acl_rules + out_acl_return_rules
            out_acl_rules = out_acl_rules + in_acl_return_rules

        in_acl_idx = self.vpp.acl_add_replace(acl_index=in_acl_idx,
                                              tag=secgroup_tag(secgroup.id,
                                                               VPP_TO_VM),
                                              rules=in_acl_rules)
        out_acl_idx = self.vpp.acl_add_replace(acl_index=out_acl_idx,
                                               tag=secgroup_tag(secgroup.id,
                                                                VM_TO_VPP),
                                               rules=out_acl_rules)
        self.secgroups[secgroup.id] = VppAcl(in_acl_idx, out_acl_idx)

        # If this is on the pending delete list it shouldn't be now
        self.deferred_delete_secgroups.discard(secgroup.id)

    def acl_delete_on_host(self, secgroup):
        """Deletes the ingress and egress VPP ACLs on host for secgroup

        This may delete up front or it may defer (and delete when it's
        next called, which is adequately fast) if there's a port using
        the ACL.

        Arguments:
        secgroup - OpenStack security group ID
        """

        # Attempt both the current ACL and any more ACLs that have been
        # previously deferred:
        self.deferred_delete_secgroups.add(secgroup)

        remaining_secgroups = set()
        for secgroup in self.deferred_delete_secgroups:

            try:
                secgroup_acls = self.secgroups[secgroup]
            except KeyError:
                LOG.error("secgroup_watcher: received request to delete "
                          "an unknown security group %s", secgroup)
                # This security group doesn't exist, don't add to the
                # deferred list
                continue

            try:
                used = False
                for iface in self.vpp.get_interfaces():
                    in_acls, out_acls = self.vpp.get_interface_acls(
                        iface['sw_if_idx'])
                    for acl_idx in secgroup_acls:
                        if acl_idx in in_acls or acl_idx in out_acls:
                            used = True
                            break
                if used:
                    LOG.debug('deferring delete of acls for secgroup %s'
                              ' as a port is using them', secgroup)
                    remaining_secgroups.add(secgroup)
                else:
                    for acl_idx in secgroup_acls:
                        self.vpp.acl_delete(acl_index=acl_idx)
                    del self.secgroups[secgroup]
                    # Discard the security group from the remote group dict
                    for remote_group in self.remote_group_secgroups:
                        self.remote_group_secgroups[
                            remote_group].discard(secgroup)
            except Exception as e:
                LOG.exception("Exception while deleting ACL %s", e)
                # We could defer this again but it's probably better
                # we move on.  Orphaned ACLs are not the end of the world.
                remaining_secgroups.add(secgroup)

        self.deferred_delete_secgroups = remaining_secgroups

    def populate_secgroup_acl_mappings(self):
        """From vpp acl dump, populate the secgroups to VppACL mapping.

        Get a dump of existing vpp ACLs that are tagged, by tag
        Decode tag info
        populate secgroups data structure relating UUID of secgroup to ACL
        self.secgroups = {secgroup_id : VppAcl(in_idx, out_idx)}
        """
        LOG.debug("Populating secgroup to VPP ACL map..")

        # Clear existing secgroups to ACL map for sanity
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

        if self.secgroups == {}:
            LOG.debug("We recovered an empty secgroups "
                      "to acl mapping. Possible reason: vpp "
                      "may have been restarted on host.")

        # py3 note: in py3 keys() does not return a list but the following
        # seems to work fine. Enclose in list() is problems arise.
        return self.secgroups.keys()

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

        except Exception:
            LOG.exception("Exception getting acl_map from vpp acl tags")
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
                LOG.debug("Still waiting for a valid vpp acl "
                          "corresponding to secgroup %s" % secgroup_id)
                return False
            else:
                vpp_acls.append(acl)

        self._set_acls_on_vpp_port(vpp_acls, sw_if_index)
        return True

    def _set_acls_on_vpp_port(self, vpp_acls, sw_if_index):
        """Build a vector of VPP ACLs and set it on the port

        Arguments -
        vpp_acls - a list of VppAcl(in_idx, out_idx) namedtuples to be set
                   on the interface. An empty list '[]' deletes all user
                   defined acls from the interface and retains only the spoof
                   ACL
        """
        # Initialize lists with anti-spoofing vpp acl indices
        spoof_acl = self.spoof_filter_on_host()
        # input acl on vpp filters egress traffic from vm and viceversa
        input_acls = [spoof_acl.out_idx]
        output_acls = [spoof_acl.in_idx]
        if vpp_acls:
            for acl in vpp_acls:
                input_acls.append(acl.out_idx)  # in on vpp == out on vm
                output_acls.append(acl.in_idx)  # out on vpp == in on vm
        # Build the vpp ACL vector
        acls = input_acls + output_acls
        # (najoy) At this point we just keep a mapping of acl vectors
        # associated with a port and do not check for any repeat application.
        self.vpp.set_acl_list_on_interface(sw_if_index,
                                           input_acls, output_acls)
        self.port_vpp_acls[sw_if_index]['l34'] = acls

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
            return ipnet(ip).version

        def _get_ip_prefix_length(ip):
            """Return the IP prefix length value

            Arguments:-
            ip - An ip IPv4 or IPv6 address (or) an IPv4 or IPv6 Network with
                 a prefix length
            If "ip" is an ip_address return its max_prefix_length
            i.e. 32 if IPv4 and 128 if IPv6
            if "ip" is an ip_network return its prefix_length
            """
            return ipnet(ip).prefixlen

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
        acl_index = self.vpp.macip_acl_add(rules=mac_ip_rules,
                                           count=len(mac_ip_rules))
        self.vpp.set_macip_acl_on_interface(sw_if_index=sw_if_index,
                                            acl_index=acl_index,
                                            )
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
            in_acl_idx, out_acl_idx = spoof_acl.in_idx, spoof_acl.out_idx
        else:
            in_acl_idx = out_acl_idx = 0xffffffff

        in_acl_idx = self.vpp.acl_add_replace(
            acl_index=in_acl_idx,
            tag=common_spoof_tag(VPP_TO_VM),
            rules=spoof_filter_rules['ingress'])

        out_acl_idx = self.vpp.acl_add_replace(
            acl_index=out_acl_idx,
            tag=common_spoof_tag(VM_TO_VPP),
            rules=spoof_filter_rules['egress'])

        # Add the new spoof ACL to secgroups mapping if it is valid
        if (in_acl_idx != 0xFFFFFFFF
                and out_acl_idx != 0xFFFFFFFF and not spoof_acl):
            spoof_acl = VppAcl(in_acl_idx, out_acl_idx)
            self.secgroups[COMMON_SPOOF_TAG] = spoof_acl
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
        return ipnet(ip_addr).network_address.packed

    def _get_snat_indexes(self, floatingip_dict):
        """Return the internal and external interface indices for SNAT.

        Ensure the internal n/w, external n/w and their corresponding
        BVI loopback interfaces are present, before returning their
        index values.
        """

        # Get internal network details.
        internal_network_data = self.ensure_network_on_host(
            floatingip_dict['internal_physnet'],
            floatingip_dict['internal_net_type'],
            floatingip_dict['internal_segmentation_id'])
        # Get the external network details
        external_network_data = self.ensure_network_on_host(
            floatingip_dict['external_physnet'],
            floatingip_dict['external_net_type'],
            floatingip_dict['external_segmentation_id'])
        if internal_network_data and external_network_data:
            int_br_idx = internal_network_data['bridge_domain_id']
            ext_br_idx = external_network_data['bridge_domain_id']
            # Return the internal and external BVI loopback intf indxs.
            return (self.ensure_bridge_bvi(int_br_idx),
                    self.ensure_bridge_bvi(ext_br_idx))
        else:
            LOG.error('Failed to ensure network on host while setting SNAT')
            return None, None

    def _delete_external_subinterface(self, floatingip_dict):
        """Check if the external subinterface can be deleted."""

        external_physnet = floatingip_dict['external_physnet']
        external_net_type = floatingip_dict['external_net_type']
        external_segmentation_id = floatingip_dict['external_segmentation_id']
        external_network_data = self.networks.get(
            (external_physnet, external_net_type, external_segmentation_id),
            None)
        if external_network_data:
            physnet_ip_addrs = self.vpp.get_interface_ip_addresses(
                external_network_data['if_uplink_idx'])
            if not physnet_ip_addrs:
                self.delete_network_on_host(
                    external_physnet, external_net_type,
                    external_segmentation_id)

    def _ensure_external_vlan_subif(self, if_name, if_idx, seg_id):
        sub_if = self.vpp.get_vlan_subif(if_name, seg_id)
        if not sub_if:
            # Create a VLAN subif
            sub_if = self.vpp.create_vlan_subif(if_idx, seg_id)
            self.vpp.ifup(sub_if)

        return sub_if

    def _get_loopback_mac(self, loopback_idx):
        """Returns the mac address of the loopback interface."""
        loopback_mac = self.vpp.get_ifidx_mac_address(loopback_idx)
        LOG.debug("mac address %s of the router BVI loopback idx: %s",
                  loopback_mac, loopback_idx)
        return loopback_mac

    def ensure_bridge_bvi(self, bridge_idx):
        """Ensure a BVI loopback interface for the bridge."""
        bvi_if_idx = self.vpp.get_bridge_bvi(bridge_idx)
        if not bvi_if_idx:
            bvi_if_idx = self.vpp.create_loopback()
            self.vpp.set_loopback_bridge_bvi(bvi_if_idx, bridge_idx)
        return bvi_if_idx

    def ensure_router_interface_on_host(self, port_id, router_data):
        """Ensure a router interface on the local host.

        Creates a loopback interface and sets the bridge's BVI to the
        loopback interface to act as an L3 gateway for the network.
        For external networks, the BVI functions as an SNAT external
        interface. For updating an interface, the service plugin removes
        the old interface and then adds the new router interface. If an
        external gateway exists, ensures a local route in VPP.

        When Layer3 HA is enabled, the router interfaces are only enabled on
        the active VPP router. The standby router keeps the interface in
        an admin down state.
        """
        # The interface could be either an external_gw or an internal router
        # interface on a subnet
        # Enable SNAT by default unless it is set to False
        enable_snat = True
        # Multiple routers on a shared external subnet is supported
        # by adding local routes in VPP.
        is_local = 0  # True for local-only VPP routes.
        # Create an external interfce if the external_gateway_info key is
        # present, else create an internal interface
        if router_data.get('external_gateway_info', False):
            seg_id = router_data['external_segmentation_id']
            net_type = router_data['external_net_type']
            physnet = router_data['external_physnet']
            vrf = 0
            is_inside = 0
            enable_snat = router_data['external_gateway_info']['enable_snat']
            external_gateway_ip = router_data['external_gateway_ip']
            # To support multiple IP addresses on a router port, add
            # the router to each of the subnets.
            gateway_ip = router_data['gateways'][0][0]
            prefixlen = router_data['gateways'][0][1]
            is_ipv6 = router_data['gateways'][0][2]
        else:
            seg_id = router_data['segmentation_id']
            net_type = router_data['net_type']
            physnet = router_data['physnet']
            vrf = router_data['vrf_id']
            is_inside = 1
            external_gateway_ip = None
            gateway_ip = router_data['gateway_ip']
            prefixlen = router_data['prefixlen']
            is_ipv6 = router_data['is_ipv6']
        # Ensure the network exists on host and get the network data
        net_data = self.ensure_network_on_host(physnet, net_type, seg_id)
        # Get the bridge domain id and ensure a BVI interface for it
        bridge_idx = net_data['bridge_domain_id']
        # Ensure a BVI (i.e. A loopback) for the bridge domain
        loopback_idx = self.vpp.get_bridge_bvi(bridge_idx)
        # Create a loopback BVI interface
        if not loopback_idx:
            # Create the loopback interface, but don't bring it UP yet
            loopback_idx = self.ensure_bridge_bvi(bridge_idx)
        # Set the VRF for tenant BVI interfaces, if not already set
        if vrf and not self.vpp.get_interface_vrf(loopback_idx) == vrf:
            self.vpp.set_interface_vrf(loopback_idx, vrf, is_ipv6)
        # Make a best effort to set the MTU on the interface
        try:
            self.vpp.set_interface_mtu(loopback_idx, router_data['mtu'])
        except SystemExit:
            # Log error and continue, do not exit here
            LOG.error("Error setting MTU on router interface")
        # Get the mac address for the route BVI loopback interface
        loopback_mac = self._get_loopback_mac(loopback_idx)
        ha_enabled = cfg.CONF.ml2_vpp.enable_l3_ha
        if ha_enabled:
            # Now bring up the loopback interface, if this router is the
            # ACTIVE router. Also populate the data structure
            # router_interface_states so the HA code can activate and
            # deactivate the interface
            if self.router_state:
                LOG.debug("Router HA state is ACTIVE")
                LOG.debug("Bringing UP the router intf idx: %s", loopback_idx)
                self.vpp.ifup(loopback_idx)
                self.router_interface_states[loopback_idx] = 1
            else:
                LOG.debug("Router HA state is BACKUP")
                LOG.debug("Bringing DOWN the router intf idx: %s",
                          loopback_idx)
                self.vpp.ifdown(loopback_idx)
                self.router_interface_states[loopback_idx] = 0
            LOG.debug("Current router interface states: %s",
                      self.router_interface_states)
        else:
            self.vpp.ifup(loopback_idx)
        # Set SNAT on the interface if SNAT is enabled
        # Get a list of all SNAT interfaces
        int_list = self.vpp.get_snat_interfaces()
        if loopback_idx not in int_list and enable_snat:
            self.vpp.set_snat_on_interface(loopback_idx, is_inside)
            # Set the SNAT 1:N overload on the external loopback interface
            if not is_inside:
                self.vpp.snat_overload_on_interface_address(loopback_idx)

        # Add GPE mappings for GPE type networks only on the master
        # node, if ha_enabled
        if net_type == TYPE_GPE and self.gpe is not None:
            if (ha_enabled and self.router_state) or not ha_enabled:
                self.gpe.add_local_gpe_mapping(seg_id, loopback_mac)
        # Set the gateway IP address on the BVI interface, if not already set
        addresses = self.vpp.get_interface_ip_addresses(loopback_idx)
        gw_ip_obj = ipaddr(gateway_ip)
        # Is there another gateway ip_addr set on this external loopback?
        if not is_inside:
            exists_gateway = any((addr for addr, _ in addresses
                                  if addr != gw_ip_obj))
            if exists_gateway:
                LOG.debug('A router gateway exists on the external network.'
                          'The current router gateway IP: %s will be added as '
                          'a local VPP route', str(gw_ip_obj))
        for address in addresses:
            if address[0] == gw_ip_obj:
                break
        else:
            # Add a local VRF route if another external gateway exists
            if not is_inside and exists_gateway:
                is_local = 1
                ip_prefix_length = 32 if gw_ip_obj.version == 4 else 128
                # Add a local IP route if it doesn't exist
                self.vpp.add_ip_route(vrf=vrf,
                                      ip_address=self._pack_address(
                                          gateway_ip),
                                      prefixlen=ip_prefix_length,
                                      next_hop_address=None,
                                      next_hop_sw_if_index=None,
                                      is_ipv6=is_ipv6,
                                      is_local=is_local)
            else:
                self.vpp.set_interface_ip(
                    loopback_idx, self._pack_address(gateway_ip), prefixlen,
                    is_ipv6)

        router_dict = {
            'segmentation_id': seg_id,
            'physnet': physnet,
            'net_type': net_type,
            'bridge_domain_id': bridge_idx,
            'bvi_if_idx': loopback_idx,
            'gateway_ip': gateway_ip,
            'prefixlen': prefixlen,
            'is_ipv6': is_ipv6,
            'mac_address': loopback_mac,
            'is_inside': is_inside,
            'external_gateway_ip': external_gateway_ip,
            'vrf_id': vrf,
            'uplink_idx': net_data.get('if_uplink_idx'),
            'is_local': is_local
            }
        if is_inside:
            LOG.debug("Router: Created inside router port: %s",
                      router_dict)
            self.router_interfaces[port_id] = router_dict
            # Ensure that all gateway networks are exported into this
            # tenant VRF &
            # A default route exists in this VRF to the external gateway
            self.export_routes_from_tenant_vrfs(
                source_vrf=router_dict['vrf_id'])
        else:
            LOG.debug("Router: Created outside router port: %s",
                      router_dict)
            self.router_external_interfaces[port_id] = router_dict
            # TODO(onong):
            # The current VPP NAT implementation supports only one outside
            # FIB table and by default it uses table 0, ie, the default vrf.
            # So, this is a temporary workaround to tide over the limitation.
            if not is_local:
                self.default_route_in_default_vrf(router_dict)
            # Ensure that the gateway network is exported into all tenant
            # VRFs, with the correct default routes
                self.export_routes_from_tenant_vrfs(
                    ext_gw_ip=router_dict['external_gateway_ip'])
        return loopback_idx

    def become_master_router(self):
        """This node will become the master router"""
        LOG.debug("VPP becoming the master router..")
        LOG.debug("Current router interface states: %s",
                  self.router_interface_states)
        for idx in self.router_interface_states:
            if not self.router_interface_states[idx]:
                LOG.debug("Bringing UP the router interface: %s", idx)
                # TODO(najoy): Bring up intf. only if not set to admin DOWN
                self.vpp.ifup(idx)
                self.router_interface_states[idx] = 1
        LOG.debug("New router interface states: %s",
                  self.router_interface_states)

    def become_backup_router(self):
        """This node will become the backup router"""
        LOG.debug("VPP becoming the standby router..")
        LOG.debug("Current router interface states: %s",
                  self.router_interface_states)
        for idx in self.router_interface_states:
            if self.router_interface_states[idx]:
                LOG.debug("Bringing DOWN the router interface: %s", idx)
                self.vpp.ifdown(idx)
                self.router_interface_states[idx] = 0
        LOG.debug("New router interface states: %s",
                  self.router_interface_states)

    def _get_ip_network(self, gateway_ip, prefixlen):
        """Returns the IP network for the gateway in CIDR form."""
        return str(ipint(gateway_ip + "/" + str(prefixlen)).network)

    def default_route_in_default_vrf(self, router_dict, is_add=True):
        # ensure that default route in default VRF is present
        if is_add:
            self.vpp.add_ip_route(
                vrf=router_dict['vrf_id'],
                ip_address=self._pack_address('0.0.0.0'),
                prefixlen=0,
                next_hop_address=self._pack_address(
                    router_dict['external_gateway_ip']),
                next_hop_sw_if_index=router_dict['bvi_if_idx'],
                is_ipv6=router_dict['is_ipv6'])
        else:
            self.vpp.delete_ip_route(
                vrf=router_dict['vrf_id'],
                ip_address=self._pack_address('0.0.0.0'),
                prefixlen=0,
                next_hop_address=self._pack_address(
                    router_dict['external_gateway_ip']),
                next_hop_sw_if_index=router_dict['bvi_if_idx'],
                is_ipv6=router_dict['is_ipv6'])

    def export_routes_from_tenant_vrfs(self, source_vrf=0, is_add=True,
                                       ext_gw_ip=None):
        """Exports the external gateway into the tenant VRF.

        The gateway network has to be exported into the tenant VRF for
        it to communicate with the outside world. Also a default route
        has to be set to the external gateway IP address.
        If source_vrf (i.e tenant VRF) is provided,
           - Export the external gateway's IP from VRF=0 into this VRF.
           - Add a default route to the external_gateway in this VRF
        Else,
           - Export the external gateway into into all tenant VRFs
           - Add a default route to the external_gateway in all tenant VRFs
        If the external gateway IP address is not provided:
        All external networks are exported into tenant VRFs

        """
        if source_vrf:
            LOG.debug("Router:Exporting external route into tenant VRF:%s",
                      source_vrf)
        else:
            LOG.debug("Router:Exporting external route into all tenant VRFs")
        # TODO(najoy): Check if the tenant ID matches for the gateway router
        # external interface and export only matching external routes.
        for ext_port in self.router_external_interfaces:
            gw_port = self.router_external_interfaces[ext_port]
            for int_port in self.router_interfaces.values():
                int_vrf = int_port['vrf_id']
                ext_vrf = gw_port['vrf_id']
                # If a source vrf is present only update if the VRF matches
                if source_vrf and int_vrf != source_vrf:
                    continue
                is_ipv6 = int_port['is_ipv6']
                default_gw_ip = "::" if is_ipv6 else '0.0.0.0'
                external_gateway_ip = gw_port['external_gateway_ip']
                if ext_gw_ip and external_gateway_ip != ext_gw_ip:
                    continue
                # Get the external and internal networks in the CIDR form
                ext_network = self._get_ip_network(
                    gw_port['gateway_ip'],
                    gw_port['prefixlen']
                    )
                int_network = self._get_ip_network(
                    int_port['gateway_ip'],
                    int_port['prefixlen']
                    )
                if is_add:
                    # Add the default route (0.0.0.0/0) to the
                    # external gateway IP addr, which is outside of VPP
                    # with the next hop sw_if_index set to the external
                    # loopback BVI address.
                    # Note: The external loopback sw_if_index and the
                    # next_hop_address is mandatory here to prevent a VPP
                    # crash - Similar to the CLI command
                    # ip route add table <int-vrf> 0.0.0.0/0 via <next-hop-ip>
                    #                                    <next-hop-sw-indx>
                    self.vpp.add_ip_route(
                        vrf=int_vrf,
                        ip_address=self._pack_address(default_gw_ip),
                        prefixlen=0,
                        next_hop_address=self._pack_address(
                            external_gateway_ip),
                        next_hop_sw_if_index=gw_port['bvi_if_idx'],
                        is_ipv6=is_ipv6)
                    # Export the external gateway subnet into the tenant VRF
                    # to enable tenant traffic to flow out. Exporting is done
                    # by setting the next hop sw if index to the loopback's
                    # sw_index (i.e. BVI) on the external network
                    # CLI: ip route add table <int_vrf> <external-subnet>
                    #                                 via <next-hop-sw-indx>
                    self.vpp.add_ip_route(
                        vrf=int_vrf,
                        ip_address=self._pack_address(ext_network),
                        prefixlen=gw_port['prefixlen'],
                        next_hop_address=None,
                        next_hop_sw_if_index=gw_port['bvi_if_idx'],
                        is_ipv6=is_ipv6)
                    # Export the tenant network into external VRF so the
                    # gateway can route return traffic to the tenant VM from
                    # the Internet.
                    # CLI: ip route add table 0 <tenant-subnet> via
                    #                                <tenant-loopback-bvi>
                    self.vpp.add_ip_route(
                        vrf=ext_vrf,
                        ip_address=self._pack_address(int_network),
                        prefixlen=int_port['prefixlen'],
                        next_hop_address=None,
                        next_hop_sw_if_index=int_port['bvi_if_idx'],
                        is_ipv6=is_ipv6)
                else:
                    self.vpp.delete_ip_route(
                        vrf=int_vrf,
                        ip_address=self._pack_address(default_gw_ip),
                        prefixlen=0,
                        next_hop_address=self._pack_address(
                            external_gateway_ip),
                        next_hop_sw_if_index=gw_port['bvi_if_idx'],
                        is_ipv6=is_ipv6)
                    # Delete the exported route in tenant VRF
                    self.vpp.delete_ip_route(
                        vrf=int_vrf,
                        ip_address=self._pack_address(ext_network),
                        prefixlen=gw_port['prefixlen'],
                        next_hop_address=None,
                        next_hop_sw_if_index=gw_port['bvi_if_idx'],
                        is_ipv6=is_ipv6)
                    # Delete the exported route from the external VRF
                    self.vpp.delete_ip_route(
                        vrf=ext_vrf,
                        ip_address=self._pack_address(int_network),
                        prefixlen=int_port['prefixlen'],
                        next_hop_address=None,
                        next_hop_sw_if_index=int_port['bvi_if_idx'],
                        is_ipv6=is_ipv6)

    def delete_router_interface_on_host(self, port_id):
        """Deletes a router interface from the host.

        Disables SNAT, if it is set on the interface.
        Deletes a loopback interface from the host, this removes the BVI
        interface from the local bridge. Also, delete the default route and
        SNAT address for the external interface.
        """
        is_external = 0

        if port_id in self.router_interfaces:
            router = self.router_interfaces[port_id]
        elif port_id in self.router_external_interfaces:
            router = self.router_external_interfaces[port_id]
            is_external = 1
            ext_intf_ip = six.u('{}/{}'.format(router['gateway_ip'],
                                               router['prefixlen']))
            # Get all local IP addresses in the external VRF belonging
            # to the same external subnet as this router.
            # Check if atleast one local_ip matches a neutron assigned
            # external IP address of the router.
            # If there's no match, there are no valid local IPs within VPP.
            local_gw_ips = [r['gateway_ip'] for
                            r in self.router_external_interfaces.values()
                            if r['is_local']]
            for local_ip in self.vpp.get_local_ip_address(ext_intf_ip,
                                                          router['is_ipv6'],
                                                          router['vrf_id']):
                # Is the local_ip valid?
                if local_ip in local_gw_ips:
                    LOG.debug('Found a router external local_ip in VPP: %s',
                              local_ip)
                    local_ip = [local_ip]
                    break
            # For-else would mean no breaks i.e. no valid local_ips
            else:
                local_ip = []
        else:
            LOG.error("Router port:%s deletion error...port not found",
                      port_id)
            return False

        net_br_idx = router['bridge_domain_id']
        bvi_if_idx = self.vpp.get_bridge_bvi(net_br_idx)
        # If an external local route, we can safetly delete it from VPP
        # Don't delete any SNAT
        if is_external and router['is_local']:
            LOG.debug("delete_router_intf: Removing the local route: %s/32",
                      router['gateway_ip'])
            prefixlen = 128 if router['is_ipv6'] else 32
            self.vpp.delete_ip_route(vrf=router['vrf_id'],
                                     ip_address=self._pack_address(
                                         router['gateway_ip']),
                                     prefixlen=prefixlen,
                                     next_hop_address=None,
                                     next_hop_sw_if_index=None,
                                     is_ipv6=router['is_ipv6'],
                                     is_local=1)
        # External router is a loopback BVI. If a local route exists,
        # replace the BVI's IP address with its IP address.
        # Don't delete the SNAT.
        elif is_external and len(local_ip) > 0:
            local_ip = local_ip[0]
            LOG.debug('delete_router_intf: replacing router loopback BVI IP '
                      'address %s with the local ip address %s',
                      router['gateway_ip'], local_ip)
            # Delete the IP address from the BVI.
            self.vpp.del_interface_ip(
                bvi_if_idx, self._pack_address(router['gateway_ip']),
                router['prefixlen'], router['is_ipv6'])
            # Delete the local route
            prefixlen = 128 if router['is_ipv6'] else 32
            self.vpp.delete_ip_route(vrf=router['vrf_id'],
                                     ip_address=self._pack_address(local_ip),
                                     prefixlen=prefixlen,
                                     next_hop_address=None,
                                     next_hop_sw_if_index=None,
                                     is_ipv6=router['is_ipv6'],
                                     is_local=1)
            self.vpp.set_interface_ip(bvi_if_idx,
                                      self._pack_address(local_ip),
                                      router['prefixlen'],
                                      router['is_ipv6'])
            # Set the router external interface corresponding to the local
            # route as non-local.
            for router in self.router_external_interfaces.values():
                if ipaddr(router['gateway_ip']) == \
                    ipaddr(local_ip):
                        router['is_local'] = 0
                        LOG.debug('Router external %s is no longer a local '
                                  'route but now assigned to the BVI', router)
        else:
            # At this point, we can safetly remove both the SNAT and BVI
            # loopback interfaces as no local routes exist.
            snat_interfaces = self.vpp.get_snat_interfaces()
            # Get SNAT out interfaces whose IP addrs are overloaded
            snat_out_interfaces = self.vpp.get_outside_snat_interface_indices()
            # delete SNAT if set on this interface
            if router['bvi_if_idx'] in snat_interfaces:
                LOG.debug('Router: Deleting SNAT on interface '
                          'index: %s', router['bvi_if_idx'])
                self.vpp.set_snat_on_interface(router['bvi_if_idx'],
                                               is_inside=router['is_inside'],
                                               is_add=False)
            # Delete the external 1:N SNAT and default routes in all VRFs
            # for external router interface deletion
            if not router['is_inside']:
                LOG.debug('Router: Deleting external gateway port %s for '
                          'router: %s', port_id, router)
                # Delete external snat addresses for the router
                if router['bvi_if_idx'] in snat_out_interfaces:
                    LOG.debug('Router:Removing 1:N SNAT on external interface '
                              'index: %s', router['bvi_if_idx'])
                    self.vpp.snat_overload_on_interface_address(
                        router['bvi_if_idx'],
                        is_add=False)
                # Delete all exported routes into tenant VRFs belonging to this
                # external gateway
                self.export_routes_from_tenant_vrfs(
                    ext_gw_ip=router['external_gateway_ip'], is_add=False)
                # delete the default route in the default VRF
                self.default_route_in_default_vrf(router, is_add=False)
            else:
                # Delete all exported routes from this VRF
                self.export_routes_from_tenant_vrfs(source_vrf=router[
                    'vrf_id'], is_add=False)
            # Delete the gateway IP address and the BVI interface if this is
            # the last IP address assigned on the BVI
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
                    if cfg.CONF.ml2_vpp.enable_l3_ha:
                        self.router_interface_states.pop(bvi_if_idx, None)
        # Remove any local GPE mappings
        if router['net_type'] == TYPE_GPE and self.gpe is not None:
            LOG.debug('Removing local GPE mappings for router '
                      'interface: %s', port_id)
            self.gpe.delete_local_gpe_mapping(router['segmentation_id'],
                                              router['mac_address'])
        if not is_external:
            self.router_interfaces.pop(port_id)
        else:
            self.router_external_interfaces.pop(port_id)

    def maybe_associate_floating_ips(self):
        """Associate any pending floating IP addresses.

        We may receive a request to associate a floating
        IP address, when the router BVI interfaces are not ready yet. So,
        we queue such requests and do the association when the router
        interfaces are ready.
        """
        LOG.debug('Router: maybe associating floating IPs: %s',
                  self.floating_ips)
        for floatingip in self.floating_ips:
            if not self.floating_ips[floatingip]['state']:
                fixedip_addr = self.floating_ips[
                    floatingip]['fixed_ip_address']
                floatingip_addr = self.floating_ips[
                    floatingip]['floating_ip_address']
                loopback_idx = self.floating_ips[floatingip]['loopback_idx']
                external_idx = self.floating_ips[floatingip]['external_idx']
                self._associate_floatingip(floatingip, fixedip_addr,
                                           floatingip_addr, loopback_idx,
                                           external_idx)

    def _associate_floatingip(self, floatingip, fixedip_addr,
                              floatingip_addr, loopback_idx, external_idx):
        """Associate the floating ip address and update state."""
        LOG.debug("Router: associating floatingip:%s with fixedip: %s "
                  "loopback_idx:%s, external_idx:%s", floatingip_addr,
                  fixedip_addr, loopback_idx, external_idx)
        snat_interfaces = self.vpp.get_snat_interfaces()

        if loopback_idx and loopback_idx not in snat_interfaces:
            self.vpp.set_snat_on_interface(loopback_idx)
        if external_idx and external_idx not in snat_interfaces:
            self.vpp.set_snat_on_interface(external_idx, is_inside=0)
        tenant_vrf = self.vpp.get_interface_vrf(loopback_idx)
        LOG.debug('Router: Tenant VRF:%s, floating IP:%s and bvi_idx:%s',
                  tenant_vrf, floatingip_addr, loopback_idx)
        # If needed, add the SNAT internal and external IP address mapping.
        snat_local_ipaddresses = self.vpp.get_snat_local_ipaddresses()
        if fixedip_addr not in snat_local_ipaddresses and tenant_vrf:
            LOG.debug("Router: setting 1:1 SNAT %s:%s in tenant_vrf:%s",
                      fixedip_addr, floatingip_addr, tenant_vrf)
            self.vpp.set_snat_static_mapping(fixedip_addr, floatingip_addr,
                                             tenant_vrf)
            # Clear any dynamic NAT sessions for the 1:1 NAT to take effect
            self.vpp.clear_snat_sessions(fixedip_addr)
            self.floating_ips[floatingip]['tenant_vrf'] = tenant_vrf
            self.floating_ips[floatingip]['state'] = True
        LOG.debug('Router: Associated floating IPs: %s', self.floating_ips)

    def associate_floatingip(self, floatingip, floatingip_dict):
        """Add the VPP configuration to support One-to-One SNAT.

        Arguments:-
        floating_ip: The UUID of the floating ip address
        floatingip_dict : The floating ip data
        """
        LOG.debug("Router: Checking for existing association for"
                  " floating ip: %s", floatingip)
        if floatingip in self.floating_ips:
            self.disassociate_floatingip(floatingip)
        else:
            LOG.debug("Router: Found no existing association for floating ip:"
                      " %s", floatingip)
        LOG.debug('Router: Associating floating ip address: %s: %s',
                  floatingip, floatingip_dict)
        loopback_idx, external_idx = self._get_snat_indexes(floatingip_dict)
        LOG.debug('Router: Retrieved floating ip intf indxs- int:%s, ext:%s',
                  loopback_idx, external_idx)
        self.floating_ips[floatingip] = {
            'fixed_ip_address': floatingip_dict['fixed_ip_address'],
            'floating_ip_address': floatingip_dict['floating_ip_address'],
            'loopback_idx': loopback_idx,
            'external_idx': external_idx,
            'state': False
            }
        tenant_vrf = self.vpp.get_interface_vrf(loopback_idx)
        # Associate the floating IP iff the router has established a tenant
        # VRF i.e. a vrf_id > 0
        if tenant_vrf:
            LOG.debug("Router: associate_floating_ip: tenant_vrf:%s BVI:%s",
                      tenant_vrf, loopback_idx)
            self.floating_ips[floatingip]['tenant_vrf'] = tenant_vrf
            self._associate_floatingip(floatingip,
                                       floatingip_dict['fixed_ip_address'],
                                       floatingip_dict['floating_ip_address'],
                                       loopback_idx,
                                       external_idx)
        else:
            self.floating_ips[floatingip]['tenant_vrf'] = 'undecided'

    def disassociate_floatingip(self, floatingip):
        """Remove the VPP configuration used by One-to-One SNAT.

        Arguments:-
        floating_ip: The UUID of the floating ip address to be disassociated.
        """
        LOG.debug('Router: Disassociating floating ip address:%s',
                  floatingip)
        # Check if we know about this floating ip address
        floatingip_dict = self.floating_ips.get(floatingip)
        if floatingip_dict:
            # Delete the SNAT internal and external IP address mapping.
            LOG.debug('Router: deleting NAT mappings for floating ip: %s',
                      floatingip)
            snat_local_ipaddresses = self.vpp.get_snat_local_ipaddresses()
            if floatingip_dict['fixed_ip_address'] in snat_local_ipaddresses:
                self.vpp.set_snat_static_mapping(
                    floatingip_dict['fixed_ip_address'],
                    floatingip_dict['floating_ip_address'],
                    floatingip_dict['tenant_vrf'],
                    is_add=0)
            self.floating_ips.pop(floatingip)
        else:
            LOG.debug('router: floating ip address: %s not found to be '
                      'disassociated', floatingip)

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


LEADIN = nvpp_const.LEADIN  # TODO(ijw): make configurable?

# TrunkWatcher thread's heartbeat interval
# TODO(onong): make it configurable if need be
TRUNK_WATCHER_HEARTBEAT = 30


class EtcdListener(object):
    def __init__(self, host, client_factory, vppf, physnets):
        self.host = host
        self.client_factory = client_factory
        self.vppf = vppf
        self.physnets = physnets
        self.pool = eventlet.GreenPool()
        self.secgroup_enabled = cfg.CONF.SECURITYGROUP.enable_security_group

        # Add GPE key-watching, if required
        if TYPE_GPE in cfg.CONF.ml2.type_drivers:
            self.gpe_listener = gpe.GpeListener(self)
        else:
            self.gpe_listener = None

        # These data structures are used as readiness indicators.
        # A port is only in here only if the attachment part of binding
        # has completed.
        # key: ifidx of port; value: (UUID, bound-callback, vpp-prop-dict)
        self.iface_state = {}
        # key: UUID of port; value: ifidx
        self.iface_state_ifidx = {}

        # Members of this are ports requiring security groups with unsatisfied
        # requirements.
        self.iface_awaiting_secgroups = {}
        # Sub-ports of a trunk with pending port bindings.
        # trunk_port ID => List(sub_ports awaiting binding)
        # When the agent is restarted, it could receive an etcd watch event
        # to bind subports even before the parent port itself is bound. This
        # dict keeps tracks of such sub_ports. They will be reconsidered
        # for binding after the parent is bound.
        self.subports_awaiting_parents = {}
        # bound subports of parent ports
        # trunk_port ID => set(bound subports)
        self.bound_subports = defaultdict(set)
        # We also need to know if the vhostuser interface has seen a socket
        # connection: this tells us there's a state change, and there is
        # a state detection function on self.vppf.
        self.vppf.vhost_ready_callback = self._vhost_ready

    def unbind(self, id):
        if id not in self.iface_state_ifidx:
            # Unbinding an unknown port
            return

        if self.iface_state_ifidx[id] in self.iface_state:
            del self.iface_state[self.iface_state_ifidx[id]]
        del self.iface_state_ifidx[id]
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
        # args['binding_type'] in ('vhostuser', 'tap'):
        # For GPE, fetch remote mappings from etcd for any "new" network
        # segments we will be binding to so we are aware of all the remote
        # overlay (mac) to underlay (IP) values
        if network_type == TYPE_GPE and self.gpe_listener is not None:
            # For GPE, a physnet value is not messaged by ML2 as it
            # is not specified for creating a gpe tenant network. Hence for
            # these net types we replace the physnet with the value of
            # gpe_locators, which stand for the physnet name.
            physnet = self.gpe_listener.physnet()
            self.gpe_listener.ensure_gpe_remote_mappings(segmentation_id)
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
            # 'None' is a special value indicating no port security
            self.iface_awaiting_secgroups[iface_idx] = None

        self.iface_state[iface_idx] = (id, bound_callback, props)
        self.iface_state_ifidx[id] = iface_idx

        self.apply_spoof_macip(iface_idx, security_data, props)

        self.maybe_apply_secgroups(iface_idx)

    def vpp_restart_prepare(self):
        """On a restart, find bound ports and clean up unwanted config

        Does the following:
        - fixes uplinks
        - identifies the ports we bound previously - they may need
          removing or updating

        Ports intended to be bound will have .bind() called later
        in the resync, which will correcly populate VPPForwarder
        structures and fix bindings whose type has changed; ports
        that are no longer needed will be unbound.

        Returns a set of bound ports
        """

        LOG.debug('Repairing physnets in VPP')
        self.vppf.fix_physnets(self.physnets)
        LOG.debug('VPP has been cleaned of stale physnets')

        return self.vppf.find_bound_ports()

    def apply_spoof_macip(self, iface_idx, security_data, props):
        """Apply non-secgroup security to a port

        This is an idempotent function to set up the port security
        (antispoof and allowed-address-pair) that can be determined
        solely from the data on the port itself.

        """

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
        # (TODO(ijw) it's also the only reason we go to iface_state)
        is_secured_port = props['bind_type'] == 'vhostuser'

        # If security-groups are enabled and it's a port needing
        # security proceed to set L3/L2 ACLs, else skip security.
        # If security-groups are empty, apply the default spoof-acls.
        # This is the correct behavior when security-groups are enabled but
        # not set on a port.
        if (self.secgroup_enabled and
                secgroup_ids is not None and  # port security off
                is_secured_port):
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
                iface_idx)

        # Remove with no error if not present
        self.iface_awaiting_secgroups.pop(iface_idx, None)

        self.maybe_up(iface_idx)

    def _vhost_ready(self, id):
        # The callback from VPP only knows the IP; convert
        # .. and note that we may not know the conversion
        iface_idx = self.iface_state_ifidx.get(id)
        if iface_idx is None:
            # Not a port we know about
            return
        self.maybe_up(iface_idx)

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
                not self.vppf.vhostuser_linked_up(id)):
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

        def _secgroup_rule(r):
            # Create a rule for the remote_ip_prefix (CIDR) value
            if r['remote_ip_addr']:
                remote_ip_prefixes = [(six.text_type(r['remote_ip_addr']),
                                       r['ip_prefix_len'])]
            # Create a rule for each ip address in the remote_group
            else:
                remote_group = r['remote_group_id']
                prefix_length = 128 if r['is_ipv6'] else 32
                ip_version = 6 if r['is_ipv6'] else 4
                # Add the referencing secgroup ID to the remote-group lookup
                # data set. This enables the RemoteGroupWatcher thread to
                # lookup the secgroups that need to be updated for a
                # remote-group etcd watch event
                self.vppf.remote_group_secgroups[remote_group].add(secgroup)
                remote_ip_prefixes = [
                    (six.text_type(ip), prefix_length) for port in
                    self.vppf.remote_group_ports[remote_group]
                    for ip in self.vppf.port_ips[port]
                    if ipnet(ip).version == ip_version]
                LOG.debug("remote_group: vppf.remote_group_ports:%s",
                          self.vppf.remote_group_ports
                          )
                LOG.debug("remote_group: vppf.port_ips:%s",
                          self.vppf.port_ips)
                LOG.debug("remote_group_ip_prefixes:%s for group %s",
                          remote_ip_prefixes, remote_group)
                LOG.debug("remote_group_secgroups: %s",
                          self.vppf.remote_group_secgroups)
            # VPP API requires the IP addresses to be represented in binary
            rules = [SecurityGroupRule(r['is_ipv6'],
                                       ipaddr(ip_addr).packed,
                                       ip_prefix_len,
                                       r.get('remote_group_id', None),
                                       r['protocol'],
                                       r['port_min'],
                                       r['port_max'])
                     for ip_addr, ip_prefix_len in remote_ip_prefixes]
            return rules

        ingress_rules, egress_rules = (
            [_secgroup_rule(r) for r in data['ingress_rules']],
            [_secgroup_rule(r) for r in data['egress_rules']]
            )
        # Flatten ingress and egress rules
        ingress_rules, egress_rules = (
            [rule for rule_list in ingress_rules for rule in rule_list],
            [rule for rule_list in egress_rules for rule in rule_list]
            )
        LOG.debug("remote_group: sec_group: %s, ingress rules: %s "
                  "egress_rules: %s", secgroup, ingress_rules, egress_rules)
        self.vppf.acl_add_replace_on_host(SecurityGroup(secgroup,
                                                        ingress_rules,
                                                        egress_rules))

    def acl_delete(self, secgroup):
        """Delete ACL on host.

        Arguments:
        secgroup - OpenStack SecurityGroup ID
        """
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
        except ValueError:
            pass  # vpp_papi throws this error when no ACLs exist
        except AttributeError:
            pass   # cannot reference acl attribute - pass and exit

    def update_remote_group_secgroups(self, remote_group):
        """Update the ACLs of all security groups that use a remote-group.

        When a remote_group to port association is changed,
        i.e. A new port is associated with (or) an existing port is removed,
        the agent needs to update the VPP ACLs belonging to all the
        security groups that use this remote-group in their rules.

        Since this is called from various threads it makes a new etcd
        client each call.
        """
        secgroups = self.vppf.remote_group_secgroups[remote_group]
        LOG.debug("Updating secgroups:%s referencing the remote_group:%s",
                  secgroups, remote_group)
        etcd_client = self.client_factory.client()
        etcd_writer = etcdutils.json_writer(etcd_client)

        for secgroup in secgroups:
            secgroup_key = self.secgroup_key_space + "/%s" % secgroup
            # TODO(najoy):Update to the new per thread etcd-client model

            # TODO(ijw): all keys really present?
            data = etcd_writer.read(secgroup_key).value

            LOG.debug("Updating remote_group rules %s for secgroup %s",
                      data, secgroup)
            self.acl_add_replace(secgroup, data)

    # EtcdListener Trunking section
    def reconsider_trunk_subports(self):
        """Try to bind subports awaiting their parent port to be bound.

        If the parent port
            - is bound
            - instance has connected to the other end of the vhostuser
            - security groups has been applied
            - is in admin UP state
        then:
            - bind the subports, and
            - set subport state to admin UP
        """
        for parent_port, subports in self.subports_awaiting_parents.items():
            LOG.debug('reconsidering bind for trunk subports %s, parent %s',
                      subports, parent_port)
            props = self.vppf.interfaces.get(parent_port, None)
            # Make sure parent port is really ready
            if (props and props['iface_idx'] in self.iface_state and
                    self.vppf.vhostuser_linked_up(parent_port) and
                    props['iface_idx'] not in self.iface_awaiting_secgroups):
                LOG.debug("Parent trunk port vhostuser ifidx %s is ready",
                          props['iface_idx'])
                self.bind_unbind_subports(parent_port, subports)
                self.subports_awaiting_parents.pop(parent_port)
            else:
                LOG.debug("Parent trunk port is not ready")

    def subports_to_unbind(self, parent_port, subports):
        """Return a list of subports to unbind for a parent port.

        subports :- A set of subports that need to be currently bound
        to the parent port.
        """
        # unbind 'bound sub-ports' that are not in the current subports
        return self.bound_subports[parent_port] - subports

    def subports_to_bind(self, parent_port, subports):
        """Return a list of subports to unbind for a parent port.

        subports :- A set of subports that need to be currently bound
        to the parent port.
        """
        # remove ports from subports that are already bound and only bind the
        # new ports.
        return subports - self.bound_subports[parent_port]

    def bind_unbind_subports(self, parent_port, subports):
        """Bind or unbind the subports of the parent ports as needed.

        To unbind all bound subports of a parent port, provide the
        parent_port argument with subports set to an empty list.
        Sample subports data structure: List of dicts

        [{"segmentation_id": 11,
         "uplink_seg_id": 149,
         "segmentation_type": "vlan",
         "uplink_seg_type": "vlan",
         "port_id": "9ee91c37-9150-49ff-9ea7-48e98547771a",
         "physnet": "physnet1"},

         {"segmentation_id": 12,
          "uplink_seg_id": 139,
          "segmentation_type": "vlan",
          "uplink_seg_type": "vlan",
          "port_id": "2b1a89ba-78f1-4350-b71a-7caf7f23cbcf",
          "physnet": "physnet1"}]

        """
        LOG.debug('Binding or Unbinding subports %s of parent trunk port %s',
                  subports, parent_port)
        subport_set = set([p['port_id'] for p in subports])
        subports_to_bind = self.subports_to_bind(parent_port, subport_set)
        LOG.debug('Binding subports %s of a parent trunk port %s',
                  subports_to_bind, parent_port)
        subports_to_unbind = self.subports_to_unbind(parent_port,
                                                     subport_set)
        LOG.debug('Unbinding subports %s of a parent trunk port %s',
                  subports_to_unbind, parent_port)
        # bind subports we are told to bind
        for subport in subports_to_bind:
            subport_data = [p for p in subports
                            if p['port_id'] == subport][0]
            LOG.debug('Binding subport %s of parent trunk port %s '
                      'sub_port_data %s',
                      subport, parent_port, subport_data)
            props = self.vppf.bind_subport_on_host(parent_port, subport_data)
            # Bring up the subport
            if props:
                self.bound_subports[parent_port].add(subport)
                subport_iface_idx = props['iface_idx']
                LOG.debug("Bringing up the trunk subport vhost ifidx %s",
                          subport_iface_idx)
                self.vppf.ifup(subport_iface_idx)
        # unbind subports we are told to unbind
        for subport in subports_to_unbind:
            LOG.debug('Unbinding subport %s of parent_port %s',
                      subport, parent_port)
            self.vppf.unbind_subport_on_host(subport)
            self.bound_subports[parent_port].remove(subport)

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
        self.remote_group_key_space = LEADIN + "/global/remote_group"
        self.trunk_key_space = LEADIN + "/nodes/%s/trunks" % self.host

        etcd_client = self.client_factory.client()
        etcd_helper = etcdutils.EtcdHelper(etcd_client)
        # We need certain directories to exist so that we can write to
        # and watch them
        etcd_helper.ensure_dir(self.port_key_space)
        etcd_helper.ensure_dir(self.secgroup_key_space)
        etcd_helper.ensure_dir(self.state_key_space)
        etcd_helper.ensure_dir(self.physnet_key_space)
        etcd_helper.ensure_dir(self.router_key_space)
        etcd_helper.ensure_dir(self.remote_group_key_space)
        etcd_helper.ensure_dir(self.trunk_key_space)

        etcd_helper.clear_state(self.state_key_space)

        # py3 note: in py3 keys() does not return a list but the following
        # seems to work fine. Enclose in list() is problems arise.
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

        self.binder = BindNotifier(self.client_factory, self.state_key_space)
        self.pool.spawn(self.binder.run)

        if self.secgroup_enabled:
            LOG.debug("loading VppAcl map from acl tags for "
                      "performing secgroup_watcher lookups")
            known_secgroup_ids = self.vppf.populate_secgroup_acl_mappings()
            LOG.debug("Adding ingress/egress spoof filters "
                      "on host for secgroup_watcher spoof blocking")
            self.spoof_filter_on_host()
            LOG.debug("Spawning secgroup_watcher..")
            self.pool.spawn(SecGroupWatcher(self.client_factory.client(),
                                            'secgroup_watcher',
                                            self.secgroup_key_space,
                                            known_secgroup_ids,
                                            heartbeat=self.AGENT_HEARTBEAT,
                                            data=self).watch_forever)
            self.pool.spawn(RemoteGroupWatcher(self.client_factory.client(),
                                               'remote_group_watcher',
                                               self.remote_group_key_space,
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

        # Spawn trunk watcher if enabled
        if 'vpp-trunk' in cfg.CONF.service_plugins:
            LOG.debug("Spawning trunk_watcher")
            self.pool.spawn(TrunkWatcher(self.client_factory.client(),
                                         'trunk_watcher',
                                         self.trunk_key_space,
                                         heartbeat=TRUNK_WATCHER_HEARTBEAT,
                                         data=self).watch_forever)

        # Spawn GPE watcher for GPE tenant networks
        if self.gpe_listener is not None:
            self.gpe_listener.spawn_watchers(self.pool,
                                             self.AGENT_HEARTBEAT,
                                             self)

        # Spawning after the port bindings are done so that
        # the RouterWatcher doesn't do unnecessary work
        if 'vpp-router' in cfg.CONF.service_plugins:
            if cfg.CONF.ml2_vpp.enable_l3_ha:
                LOG.info("L3 HA is enabled")
            LOG.debug("Spawning router_watcher")
            self.pool.spawn(RouterWatcher(self.client_factory.client(),
                                          'router_watcher',
                                          self.router_key_space,
                                          heartbeat=self.AGENT_HEARTBEAT,
                                          data=self).watch_forever)

        self.pool.waitall()


class PortWatcher(etcdutils.EtcdChangeWatcher):

    def __init__(self, *args, **kwargs):
        super(PortWatcher, self).__init__(*args, **kwargs)
        self.etcd_client.write(LEADIN + '/state/%s/alive' %
                               self.data.host,
                               1, ttl=3 * self.heartbeat)

    def do_tick(self):
        # The key that indicates to people that we're alive
        # (not that they care)
        self.etcd_client.refresh(LEADIN + '/state/%s/alive' %
                                 self.data.host,
                                 ttl=3 * self.heartbeat)

    def init_resync_start(self):
        """Identify known ports in VPP

        We are beginning a resync because the agent has
        restarted.  We should be fixing VPP with the least
        disruption possible so that traffic being passed by VPP
        on currently configured ports is not disrupted.  As such,
        this goes to find correctly configured ports (which -
        if still required - will be left alone) and removes
        structures that have been partially or incorrectly set up.
        """
        self.expected_keys = self.data.vpp_restart_prepare()

    def removed(self, port):
        # Removing key == desire to unbind

        try:
            is_gpe = False
            port_data = self.data.vppf.interfaces[port]
            port_net = port_data['net_data']
            is_gpe = port_net['network_type'] == TYPE_GPE \
                and self.data.gpe_listener is not None

            if is_gpe:
                # Get seg_id and mac to delete any gpe mappings
                seg_id = port_net['segmentation_id']
                mac = port_data['mac']
        except KeyError:
            # On initial resync, this information may not
            # be available; also, the network may not
            # be gpe
            if is_gpe:
                LOG.warning('Unable to delete GPE mappings for port')

        self.data.unbind(port)

        # Unlike bindings, unbindings are immediate.

        try:
            self.etcd_client.delete(
                self.data.state_key_space + '/%s'
                % port)
            if is_gpe:
                self.data.gpe_listener.delete_etcd_gpe_remote_mapping(
                    seg_id, mac)
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

        data = jsonutils.loads(value)

        # For backward comatibility reasons, 'plugtap' now means 'tap'
        # Post-17.07 'tap' is used, but this allows compatibility with
        # previously stored information in etcd.
        binding_type = data['binding_type']
        if binding_type == 'plugtap':
            binding_type = 'tap'

        self.data.bind(
            self.data.binder.add_notification,
            port,
            binding_type,
            None,  # We will set this closer to the actual vpp call
            data['physnet'],
            data['network_type'],
            data['segmentation_id'],
            data  # TODO(ijw) convert incoming to security fmt
            )
        # While the bind might fail for one reason or another,
        # we have nothing we can do at this point.  We simply
        # decline to notify Nova the port is ready.

        # For GPE networks,
        # write the remote mapping data to etcd to
        # propagate both the mac to underlay mapping and
        # mac to instance's IP (for ARP) mapping to all
        # agents that bind this segment using GPE
        if data['network_type'] == TYPE_GPE \
                and self.data.gpe_listener is not None:
            props = self.data.vppf.interfaces[port]
            mac = props['mac']
            for ip in [ip['ip_address'] for ip in data.get('fixed_ips')]:
                self.data.gpe_listener.add_etcd_gpe_remote_mapping(
                    data['segmentation_id'], mac, ip)


class RouterWatcher(etcdutils.EtcdChangeWatcher):
    """Start an etcd watcher for router operations.

    Starts an etcd watcher on the /router directory for
    this node. This watcher is responsible for consuming
    Neutron router CRUD operations.
    """

    # TODO(ijw): consider how to remove GPE references from the router
    # code, as they *should* be dealt with by port binding functions.

    def do_tick(self):
        pass

    def parse_key(self, router_key):
        """Parse the key into two tokens and return a tuple.

        The returned tuple is denoted by (token1, token2).
        If token1 == "floatingip", then token2 is the ID of the
        floatingip that is added or removed on the server.
        If, token1 == router_ID and token2 == port_ID of the router
        interface that is added or removed.
        If, token1 == 'ha', then we return that token for router watcher
        to action.
        """
        m = re.match('([^/]+)' + '/([^/]+)', router_key)
        floating_ip, router_id, port_id = None, None, None
        if m and m.group(1) and m.group(2):
            if m.group(1) == 'floatingip':
                floating_ip = m.group(2)
                return ('floatingip', floating_ip)
            else:
                router_id = m.group(1)
                port_id = m.group(2)
                return (router_id, port_id)
        else:
            return (None, None)

    def add_remove_gpe_mappings(self, port_id, router_data, is_add=1):
        """Add a GPE mapping to the router's loopback mac-address."""
        if router_data.get('external_gateway_info', False):
            loopback_mac = self.data.vppf.router_external_interfaces[
                port_id]['mac_address']
        else:
            loopback_mac = self.data.vppf.router_interfaces[
                port_id]['mac_address']
        # GPE remote mappings are added for only the master L3 router,
        # if ha_enabled
        ha_enabled = cfg.CONF.ml2_vpp.enable_l3_ha
        if is_add:
            if (ha_enabled and self.data.vppf.router_state) or not ha_enabled:
                self.data.gpe_listener.add_etcd_gpe_remote_mapping(
                    router_data['segmentation_id'],
                    loopback_mac,
                    router_data['gateway_ip'])
        else:
            self.data.gpe_listener.delete_etcd_gpe_remote_mapping(
                router_data['segmentation_id'],
                loopback_mac)

    def added(self, router_key, value):
        token1, token2 = self.parse_key(router_key)
        if token1 and token2:
            if token1 != 'floatingip':
                port_id = token2
                router_data = jsonutils.loads(value)
                self.data.vppf.ensure_router_interface_on_host(
                    port_id, router_data)
                self.data.vppf.maybe_associate_floating_ips()
                if router_data.get('net_type') == TYPE_GPE:
                    self.add_remove_gpe_mappings(port_id, router_data,
                                                 is_add=1)
            else:
                floating_ip = token2
                floatingip_dict = jsonutils.loads(value)
                self.data.vppf.associate_floatingip(floating_ip,
                                                    floatingip_dict)
        if cfg.CONF.ml2_vpp.enable_l3_ha and router_key == 'ha':
            LOG.debug('Setting VPP-Router HA State..')
            router_state = bool(jsonutils.loads(value))
            LOG.debug('Router state is: %s', router_state)
            # Become master if a state is True, else become backup
            state = 'MASTER' if router_state else 'BACKUP'
            LOG.debug('VPP Router HA state has become: %s', state)
            self.data.vppf.router_state = router_state
            if router_state:
                self.data.vppf.become_master_router()
            else:
                self.data.vppf.become_backup_router()
            # Update remote mappings for GPE bound router ports
            self.data.gpe_listener.update_router_gpe_mappings()

    def removed(self, router_key):
        token1, token2 = self.parse_key(router_key)
        if token1 and token2:
            if token1 != 'floatingip':
                port_id = token2
                router_data = self.data.vppf.router_interfaces.get(port_id)
                # Delete the GPE mapping first as we need to lookup the
                # router interface mac-address from vppf
                if router_data and router_data.get('net_type') == TYPE_GPE:
                    self.add_remove_gpe_mappings(port_id, router_data,
                                                 is_add=0)
                self.data.vppf.delete_router_interface_on_host(port_id)
            else:
                floating_ip = token2
                self.data.vppf.disassociate_floatingip(floating_ip)


class SecGroupWatcher(etcdutils.EtcdChangeWatcher):

    def __init__(self, etcd_client, name, watch_path,
                 known_keys,
                 **kwargs):
        self.known_keys = known_keys
        super(SecGroupWatcher, self).__init__(
            etcd_client, name, watch_path, **kwargs)

    def init_resync_start(self):
        # TODO(ijw): we should probably do the secgroup work
        # here rather than up front
        return self.known_keys

    def do_tick(self):
        pass

    def removed(self, secgroup):
        self.data.acl_delete(secgroup)

    def added(self, secgroup, value):
        # create or update a secgroup == add_replace vpp acl
        data = jsonutils.loads(value)
        self.data.acl_add_replace(secgroup, data)

        self.data.reconsider_port_secgroups()


class RemoteGroupWatcher(etcdutils.EtcdChangeWatcher):
    """Details on how the remote-group-id rules are updated by the vpp-agent.

    This thread watches the remote-group key space.
    When VM port associations to security groups are updated, this thread
    receives an etcd watch event from the server. From the watch event,
    the thread figures out the set of ports associated with the
    remote-group-id and the IP addresses of each port.

    After this, this thread updates two data structures.
    The first one is a dictionary named port_ips, used to keep track of
    the ports to their list of IP addresses. It has the port UUID as the key,
    and the value is it's set of IP addresses. The second DS is a dict named
    remote_group_ports. This is used to keep track of port memberships in
    remote-groups. The key is the remote_group_id and the value is the set of
    ports associated with it. These two dictionaries are updated by the thread
    whenever watch events are received, so the agent always has up to date
    information on ports, their IPs and the remote-groups association.

    The RemoteGroupWatcher  thread then calls a method named
    update_remote_group_secgroups with the remote_group_id as the argument.
    This method figures out which secgroups need to be updated as a result of
    the watch event. This is done by looking up another dict named
    remote_group_secgroups that keeps track of all the secgroups that are
    referencing the remote-group-id inside their rules.
    The key is the remote-group, and the value is the set of secgroups that
    are dependent on it.

    The update_remote_group_secgroups method then reads the rules for each of
    these referencing security-groups and sends it to the method named
    acl_add_replace with the security-group-uuid and rules as the argument.The
    acl_add_replace method takes each rule that contains the remote-group-id
    and computes a product using the list of IP addresses belonging to all
    the ports in the remote-group. It then calls the acl_add_replace method
    in vppf to atomically update the relevant VPP ACLs for the security-group.

    """

    def do_tick(self):
        pass

    def parse_key(self, remote_group_key):
        m = re.match('([^/]+)' + '/([^/]+)', remote_group_key)
        remote_group_id, port_id = None, None
        if m:
            remote_group_id = m.group(1)
            port_id = m.group(2)
        return (remote_group_id, port_id)

    def added(self, remote_group_key, value):
        # remote_group_key format is "remote_group_id/port_id"
        # Value is a list of IP addresses
        remote_group_id, port_id = self.parse_key(remote_group_key)
        if value and remote_group_id and port_id:
            ip_addrs = jsonutils.loads(value)
            # The set of IP addresses configured on a port
            self.data.vppf.port_ips[port_id] = set(ip_addrs)
            # The set of ports in a security-group
            self.data.vppf.remote_group_ports[remote_group_id].update(
                [port_id])
            LOG.debug("Current remote_group_ports: %s port_ips: %s",
                      self.data.vppf.remote_group_ports,
                      self.data.vppf.port_ips)
            self.data.update_remote_group_secgroups(remote_group_id)

    def removed(self, remote_group_key):
        remote_group_id, port_id = self.parse_key(remote_group_key)
        if remote_group_id and port_id:
            # Remove the port_id from the remote_group
            self.data.vppf.remote_group_ports[
                remote_group_id].difference_update([port_id])
            LOG.debug("Current remote_group_ports: %s port_ips: %s",
                      self.data.vppf.remote_group_ports,
                      self.data.vppf.port_ips)
            self.data.update_remote_group_secgroups(remote_group_id)


class TrunkWatcher(etcdutils.EtcdChangeWatcher):
    """Watches trunk parent/subport bindings on the host and takes actions.

    Trunk keyspace format.
    /networking-vpp/nodes/<node-name>/trunks/<UUID of the trunk>

    Sample data format:
    {"status": "ACTIVE",
     "name": "trunk-new",
     "admin_state_up": true,
     "sub_ports": [
         {"segmentation_id": 11,
          "uplink_seg_id": 149,
          "segmentation_type": "vlan",
          "uplink_seg_type": "vlan",
          "port_id": "9ee91c37-9150-49ff-9ea7-48e98547771a",
          "physnet": "physnet1"},

         {"segmentation_id": 12,
          "uplink_seg_id": 139,
          "segmentation_type": "vlan",
          "uplink_seg_type": "vlan",
          "port_id": "2b1a89ba-78f1-4350-b71a-7caf7f23cbcf",
          "physnet": "physnet1"}],
    }
    How does it work?
    The ml2 server:
    1) Writes above etcd key/value when a trunk port is bound on the host.
    2) Updates the above value when subports on a bound trunk are updated.
    3) Deletes the key when the trunk is unbound.
    The trunkwatcher receives the watch event and it figures out whether
    it should perform a bind or unbind action on the parent and its subport
    and performs it.
    """

    def do_tick(self):
        """Invoked every TRUNK_WATCHER_HEARTBEAT secs"""
        # Check if there are child ports to be bound and brought UP
        self.data.reconsider_trunk_subports()

    def added(self, parent_port, value):
        """Bind and unbind sub-ports of the parent port."""
        data = jsonutils.loads(value)
        LOG.debug('trunk watcher received add for parent_port %s '
                  'with data %s', parent_port, data)
        # Due to out-of-sequence etcd watch events during an agent restart,
        # we do not yet know at this point whether the parent port is setup.
        # So, we'll add it to the awaiting parents queue and reconsider it.
        self.data.subports_awaiting_parents[parent_port] = data['sub_ports']
        # reconsider awaiting sub_ports
        self.data.reconsider_trunk_subports()

    def removed(self, parent_port):
        """Unbind all sub-ports and then unbind the parent port."""
        LOG.debug('trunk watcher received unbound for parent port %s ',
                  parent_port)
        # First, unbind all subports
        self.data.bind_unbind_subports(parent_port, subports=[])
        # Then, unbind the parent port if it has no subports
        if not self.data.bound_subports[parent_port]:
            LOG.debug('Unbinding the parent port %s', parent_port)
            self.data.vppf.unbind_interface_on_host(parent_port)


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
        self.etcd_writer = etcdutils.json_writer(self.etcd_client)

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

                # TODO(ijw): do we ever clean this space up?
                self.etcd_writer.write(
                    self.state_key_space + '/%s' % port,
                    props)
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


def openstack_base_setup(process_name):
    """General purpose entrypoint

    Sets up non-specific bits (the integration with OpenStack and its
    config, and so on).
    """
    # Arguments, config files and options
    cfg.CONF(sys.argv[1:])

    # General logging
    logging.setup(cfg.CONF, process_name)

    # Guru meditation support enabled
    gmr_opts.set_defaults(cfg.CONF)
    gmr.TextGuruMeditation.setup_autorun(
        version.version_info,
        service_name='vpp-agent')


def main():
    """Main function for VPP agent functionality."""

    openstack_base_setup('vpp_agent')

    setup_privsep()

    compat.register_ml2_base_opts(cfg.CONF)
    compat.register_securitygroups_opts(cfg.CONF)
    config_opts.register_vpp_opts(cfg.CONF)

    # Pull physnets out of config and interpret them
    if not cfg.CONF.ml2_vpp.physnets:
        LOG.critical("Missing physnets config. Exiting...")
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
                          "physnet2:<interface>")
                sys.exit(1)
            if len(v) > MAX_PHYSNET_LENGTH:
                LOG.error("Physnet '%(physnet_name)s' is longer than "
                          "%(len)d characters.",
                          {'physnet_name': v, 'len': MAX_PHYSNET_LENGTH})
                sys.exit(1)
            physnets[k] = v

    # Deal with VPP-side setup

    if cfg.CONF.ml2_vpp.enable_vpp_restart:
        VPPRestart().wait()

    # Convert to the minutes unit that VPP uses:
    # (we round *up*)
    # py3 note: using // since we want integer division
    mac_age_min = int((cfg.CONF.ml2_vpp.mac_age + 59) // 60)
    vppf = VPPForwarder(physnets,
                        mac_age=mac_age_min,
                        vpp_cmd_queue_len=cfg.CONF.ml2_vpp.vpp_cmd_queue_len,
                        read_timeout=cfg.CONF.ml2_vpp.read_timeout
                        )

    # Deal with etcd-side setup

    LOG.debug("Using etcd host:%s port:%s user:%s password:***",
              cfg.CONF.ml2_vpp.etcd_host,
              cfg.CONF.ml2_vpp.etcd_port,
              cfg.CONF.ml2_vpp.etcd_user)

    client_factory = etcdutils.EtcdClientFactory(cfg.CONF.ml2_vpp)

    # Do the work

    ops = EtcdListener(cfg.CONF.host, client_factory, vppf, physnets)

    names = cfg.CONF.ml2_vpp.vpp_agent_extensions
    if names is not '':
        mgr = ExtensionManager(
            'networking_vpp.vpp_agent.extensions',
            names,
            VPPAgentExtensionBase)
        mgr.call_all('run', cfg.CONF.host, client_factory, vppf, ops.pool)

    ops.process_ops()

if __name__ == '__main__':
    main()
