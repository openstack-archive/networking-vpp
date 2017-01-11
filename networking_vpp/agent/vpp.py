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


import enum
import eventlet
import fnmatch
import grp
from ipaddress import ip_address
import os
import pwd
import time
import vpp_papi

L2_VTR_POP_1 = 3


def mac_to_bytes(mac):
    """ Pack a MAC into a byte array."""
    return str(''.join(chr(int(x, base=16)) for x in mac.split(':')))

def fix_string(s):
    """Deal with VPP returns by turning them into a legible string."""
    return s.rstrip("\0").decode(encoding='ascii')

def pack_ipaddress(self, ip_addr):
    """Pack an IPv4 or IPv6 ip_addr into binary."""
    return ip_address(unicode(ip_addr)).packed

def _get_ip_version(ip):
    """Return the IP Version 4 or 6"""
    ip_addr = ip_address(ip)
    return ip_addr.version

def mac_ip_acl_rule_from_input(in):
    """Convert the world-format macip rule to one VPP likes for function calls.

    input has is_permit, src_mac, src_ip_addr.

    input may have src_ip_prefix_len but it's intended to be a
    complete match if not supplied

    input may have src_mac_mask by it's intended to be a complete match if
    not supplied

    output requires these to be packed, needs is_ipv6
    """

    mandatory = set(['is_permit', 'src_mac', 'src_ip_addr'])
    allowed = y.union(['src_ip_prefix_len', 'src_mac_mask'])

    
    # Validate keys of input
    if not allowed.issuperset(in.keys()):
        # Additional keys
        raise ValueError('mac_ip acl with too many keys')

    if not mandatory.issubset(in.keys()):
        # Missing keys
        raise ValueError('mac_ip acl with missing mandatory keys')
        
    vpp_acl = {}
    vpp_acl['is_permit'] = in['is_permit']
    vpp_acl['src_mac'] = mac_to_bytes(in['src_mac'])
    vpp_acl['src_mac'] = mac_to_bytes(in.get('src_mac_mask', 'ff:ff:ff:ff:ff:ff'))
    src_addr = in['src_addr']
    ip_version=ip_version(src_addr)
    vpp_acl['is_ipv6'] = 1 if ip_version == 6 else 0
    vpp_acl['src_ip_addr'] = pack_ipaddress(src_addr)
    full_ip_prefix = 32 if ip_version == 4 else 128
    vpp_acl['src_ip_prefix_len'] = int(in.get('src_ip_prefix_len', full_ip_prefix))

    return vpp_acl

def l3_ip_acl_rule_from_input(in):
    """Convert the world-format l3 rule to one VPP likes for function calls.

    input has is_permit, src_mac, src_ip_addr.

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

    input may have src_ip_prefix_len but it's intended to be a
    complete match if not supplied

    input may have src_mac_mask by it's intended to be a complete match if
    not supplied

    output requires these to be packed, needs is_ipv6
    """

    mandatory = set(['is_permit',
                     'src_ip_addr', 'dst_ip_addr',
                     'proto',
                     'srcport_or_icmptype_first',
                     'srcport_or_icmptype_last',
                     'dstport_or_icmpcode_first',
                     'dstport_or_icmpcode_last'
                     ])
    allowed = y.union(['src_ip_prefix_len', 'dst_ip_prefix_len'])

    # Validate keys of input
    if not allowed.issuperset(in.keys()):
        # Additional keys
        raise ValueError('l3 acl with too many keys')

    if not mandatory.issubset(in.keys()):
        # Missing keys
        raise ValueError('l3 acl with missing mandatory keys')
        
    vpp_acl = {}
    vpp_acl['is_permit'] = in['is_permit']

    src_addr = in['src_addr']
    ip_version=ip_version(src_addr)
    vpp_acl['is_ipv6'] = 1 if ip_version == 6 else 0
    vpp_acl['src_ip_addr'] = pack_ipaddress(src_addr)
    full_ip_prefix = 32 if ip_version == 4 else 128
    vpp_acl['src_ip_prefix_len'] = int(in.get('src_ip_prefix_len', full_ip_prefix))

    dst_addr = in['dst_addr']
    if ip_version != ip_version(dst_addr):
        raise ValueError('l3 acl with differing address families')
    vpp_acl['dst_ip_addr'] = pack_ipaddress(dst_addr)
    vpp_acl['dst_ip_prefix_len'] = int(in.get('dst_ip_prefix_len', full_ip_prefix))

    return vpp_acl

def singleton(cls):
    instances = {}

    def getinstance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return getinstance


@singleton
class VPPInterface(object):
    """Interface that wraps VPP API to produce consumable functions.

    The rules:

    - these are atomic - they either change state in VPP or they don't.  They
      shouldn't be hiding multiple functions that change state
      inside.  That way, we know that VPP is either in the new state
      (success) or the old (if there's a crash) which makes recovery easier.
    - these should not return success or failure.  If they fail they
      should throw an error.
    - they should conceal the VPP API datastructures.  These are
      subject to change with VPP version, so we should break out the
      relevant values
    - they should conceal weirdnesses of the interface (largely this
      means running fix_string() on every string that comes back to get
      rid of its trailing zeros)
    """

    def _check_retval(self, t):
        """See if VPP returned OK.

        VPP is very inconsistent in return codes, so for now this reports
        a logged warning rather than flagging an error.
        """

        try:
            if t.retval != 0:
                self.LOG.error('FAIL? retval here is %s', t.retval)
                # TODO(ijw): get the VPP interface consistent and add a raise
        except AttributeError as e:
            self.LOG.debug("Unexpected request format.  Error: %s on %s"
                           % (e, t))

    def get_vhostusers(self):
        t = self._vpp.sw_interface_vhost_user_dump()

        for interface in t:
            yield (fix_string(interface.interface_name), interface)

    def get_interfaces(self):
        t = self._vpp.sw_interface_dump()

        for interface in t:
            yield (fix_string(interface.interface_name), interface)

    def get_ifidx_by_name(self, name):
        for (ifname, f) in self.get_interfaces():
            if ifname == name:
                return f.sw_if_index
        return None

    def get_version(self):
        t = self._vpp.show_version()

        self._check_retval(t)

        return fix_string(t.version)

    ########################################

    def create_tap(self, ifname, mac):
        # (we don't like unicode in VPP hence str(ifname))
        t = self._vpp.tap_connect(use_random_mac=False,
                                  tap_name=str(ifname),
                                  mac_address=mac_to_bytes(mac),
                                  renumber=False,
                                  custom_dev_instance=0)

        self._check_retval(t)

        return t.sw_if_index  # will be -1 on failure (e.g. 'already exists')

    def delete_tap(self, idx):
        self._vpp.tap_delete(sw_if_index=idx)

        # Err, I just got a sw_interface_set_flags here, not a delete tap?
        # self._check_retval(t)

    #############################

    def create_vhostuser(self, ifpath, mac,
                         qemu_user=None, qemu_group=None, is_server=False):
        self.LOG.info('Creating %s as a port', ifpath)

        t = self._vpp.create_vhost_user_if(is_server=is_server,
                                           sock_filename=str(ifpath),
                                           renumber=False,
                                           custom_dev_instance=0,
                                           use_custom_mac=True,
                                           mac_address=mac_to_bytes(mac)
                                           )
        self.LOG.debug("Created vhost user interface object: %s", str(t))
        self._check_retval(t)

        if is_server:
            # The permission that qemu runs as.
            self.LOG.info(('Changing vhostuser interface file permission '
                           'to %s:%s'),
                          (qemu_user, qemu_group))
            uid = pwd.getpwnam(qemu_user).pw_uid
            gid = grp.getgrnam(qemu_group).gr_gid
            os.chown(ifpath, uid, gid)
            os.chmod(ifpath, 0o770)

        return t.sw_if_index

    def delete_vhostuser(self, idx):
        self.LOG.debug("Deleting VPP interface - index: %s", idx)
        t = self._vpp.delete_vhost_user_if(sw_if_index=idx)

        self._check_retval(t)

    ########################################
    def __init__(self, log):
        self.LOG = log
        jsonfiles = []
        for root, dirnames, filenames in os.walk('/usr/share/vpp/api/'):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                jsonfiles.append(os.path.join(root, filename))

        self._vpp = vpp_papi.VPP(jsonfiles)
        # Sometimes a callback fires unexpectedly.  We need to catch them
        # because vpp_papi will traceback otherwise
        self._vpp.register_event_callback(self._cb)

        self.registered_callbacks = {}
        for event in self.CallbackEvents:
            self.registered_callbacks[event] = []

        self._vpp.connect("python-VPPInterface")
        eventlet.spawn_n(self.vpp_watcher_thread)

    ########################################
    class CallbackEvents(enum.Enum):
        """Enum of possible events from vpp.

        This enum is constructed as a 2 tuple, containing:
        - the name of the method to call, assuming all want_* methods
          will have the following prototype: want_*(enable, pid)
        - the returned type name, which is used to forward the event
          to the appropriate callback.
        """
        INTERFACE = ('want_interface_events',
                     'sw_interface_set_flags')
        STATISTICS = ('want_stats',
                      'vnet_interface_counters')
        OAM = ('want_oam_events',
               'oam_event')

        # These events are not generated by VPP itself, but artificially by
        # a background thread watching VPP.
        VHOST_USER_CONNECT = (None,
                              'XXXvhost_user_connect')

    def _cb(self, msg_name, data):
        """VPP callback.

        - msg_name: name of the message type
        - data: the data within the message
        """
        for event in self.CallbackEvents:
            (unused, event_data_name) = event.value
            if msg_name == event_data_name:
                for callback in self.registered_callbacks[event]:
                    callback(data)

    def register_for_events(self, event, target):
        if target in self.registered_callbacks[event]:
            raise Exception('Target %s already registered for Event %s',
                            str(target), str(event))
        self.registered_callbacks[event].append(target)
        if len(self.registered_callbacks[event]) == 1:
            (method_name, event_cls) = event.value
            if method_name is not None:
                register_method = getattr(self._vpp, method_name)
                register_method(enable_disable=1, pid=os.getpid())

    def unregister_for_event(self, event, target):
        if target not in self.registered_callbacks[event]:
            raise Exception('Target %s not registered for Event %s',
                            str(target), str(event))
        self.registered_callbacks[event].remove(target)
        if len(self.registered_callbacks[event]) == 0:
            (method_name, event_cls) = event.value
            if method_name is not None:
                register_method = getattr(self._vpp, method_name)
                register_method(enable_disable=0, pid=os.getpid())

    def vpp_watcher_thread(self):
        prev_seen = set()
        while True:
            ifs = {}
            try:
                time.sleep(1)  # TODO(ijw) - this needs a real callback
                for name, data in self.get_vhostusers():
                    if data.sock_errno == 0:  # connected, near as we can tell
                        ifs[data.sw_if_index] = data
                seen = set(ifs.keys())

                newly_seen = seen - prev_seen
                for f in newly_seen:
                    self._cb('XXXvhost_user_connect', ifs[f])
                prev_seen = seen
            except Exception:
                self.LOG.exception('Exception in vhostuser watcher thread')

    ########################################

    def disconnect(self):
        self._vpp.disconnect()

    ########################################

    def create_bridge_domain(self, id, mac_age):
        t = self._vpp.bridge_domain_add_del(
            bd_id=id,  # the numeric ID of this domain
            flood=True,  # enable bcast and mcast flooding
            uu_flood=True,  # enable unknown ucast flooding
            forward=True,  # enable forwarding on all interfaces
            learn=True,  # enable learning on all interfaces
            arp_term=False,  # enable ARP termination in the BD
            mac_age=mac_age,  # set bridge domain MAC aging TTL
            is_add=True  # is an add
        )
        self._check_retval(t)

    def delete_bridge_domain(self, id):
        t = self._vpp.bridge_domain_add_del(
            bd_id=id,  # the numeric ID of this domain
            flood=True,  # enable bcast and mcast flooding
            uu_flood=True,  # enable unknown ucast flooding
            forward=True,  # enable forwarding on all interfaces
            learn=True,  # enable learning on all interfaces
            arp_term=False,  # enable ARP termination in the BD
            is_add=False  # is a delete
        )
        self._check_retval(t)

    ########################################

    def create_vlan_subif(self, if_id, vlan_tag):
        self.LOG.debug("Creating vlan subinterface with ID:%s and vlan_tag:%s"
                       % (if_id, vlan_tag))
        t = self._vpp.create_vlan_subif(
            sw_if_index=if_id,
            vlan_id=vlan_tag)

        self._check_retval(t)

        # pop vlan tag from subinterface
        self.set_vlan_remove(t.sw_if_index)

        return t.sw_if_index

    def delete_vlan_subif(self, sw_if_index):
        self.LOG.debug("Deleting subinterface with sw_if_index: %s"
                       % (sw_if_index))
        t = self._vpp.delete_subif(sw_if_index=sw_if_index)

        self._check_retval(t)
        return

    ########################################

    def acl_add_replace(self, acl_index, rules, tag=None):
        self.LOG.debug("Add_Replace vpp acl with indx %s tag %s rules %s ",
                       acl_index, tag, rules))
        rules = [l3_ip_acl_rule_from_input(f) for f in rules]
        t = self._vpp.acl_add_replace(acl_index=acl_index,
                                      tag=str(tag),
                                      r=rules,
                                      count=len(rules))
        self._check_retval(t)
        return t.acl_index

    def set_acl_list_on_interface(self, sw_if_index, n_input, acls):
        self.LOG.debug("Setting ACL vector %s on VPP interface %s"
                       % (acls, sw_if_index))
        # n_input: the first N acls are ingress acls, the remains are egress
        t = self._vpp.acl_interface_set_acl_list(sw_if_index=sw_if_index,
                                                 count=len(acls),
                                                 n_input=n_input,
                                                 acls=acls)

        self._check_retval(t)

    def acl_delete(self, acl_index):
        self.LOG.debug("Deleting vpp acl index %s" % acl_index)
        t = self._vpp.acl_del(acl_index=acl_index)
        self._check_retval(t)

    def get_acl_tags(self):
        for f in self._vpp.acl_dump(acl_index=0xffffffff):
            yield f.sw_if_index, fix_string(f.tag)
            

    ########################################

    def macip_acl_add(self, rules):
        self.LOG.debug("Adding macip acl with rules %s"
                       % (rules))

        rules = [mac_ip_acl_rule_from_input(f) for f in rules]
        t = self._vpp.macip_acl_add(count=len(rules),
                                    r=rules)
        self._check_retval(t)
        return t.acl_index

    def set_macip_acl_on_interface(self, sw_if_index, acl_index):
        self.LOG.debug("Setting macip acl %s on VPP interface %s"
                       % (acl_index, sw_if_index))
        t = self._vpp.macip_acl_interface_add_del(is_add=1,
                                                  sw_if_index=sw_if_index,
                                                  acl_index=acl_index)
        self._check_retval(t)

    def delete_macip_acl(self, acl_index):
        self.LOG.debug("Deleting macip acl index %s" % acl_index)
        t = self._vpp.macip_acl_del(acl_index=acl_index)
        self._check_retval(t)

    def get_macip_acl_dump(self):
        self.LOG.debug("Getting the MAC-IP Interface ACL dump")
        t = self._vpp.macip_acl_interface_get()
        self._check_retval(t)

        for sw_index, acl_index in t.acls:
            yield sw_index, acl_index

#    def create_srcrep_vxlan_subif(self, vrf_id, src_addr, bcast_addr, vnid):
#        t = self._vpp.vxlan_add_del_tunnel(
#            True,  # is_add
#            src_addr,
#            bcast_addr,
#            vrf_id,
#            decap_next_index,   # what is this?
#            vni)
#
#        self._check_retval(t)
#
#        return t.sw_if_index
    ########################################

    def set_vlan_remove(self, if_id):
        self.set_vlan_tag_rewrite(if_id, L2_VTR_POP_1, 0, 0, 0)

    def set_vlan_tag_rewrite(self, if_id, vtr_op, push_dot1q, tag1, tag2):
        t = self._vpp.l2_interface_vlan_tag_rewrite(
            sw_if_index=if_id,
            vtr_op=vtr_op,
            push_dot1q=push_dot1q,
            tag1=tag1,
            tag2=tag2)
        self._check_retval(t)

    def add_to_bridge(self, bridx, *ifidxes):
        for ifidx in ifidxes:
            t = self._vpp.sw_interface_set_l2_bridge(
                rx_sw_if_index=ifidx, bd_id=bridx,
                bvi=False,                  # BVI (no thanks)
                shg=0,                      # shared horizon group
                enable=True)                # enable bridge mode
            self._check_retval(t)

    def delete_from_bridge(self, *ifidxes):
        for ifidx in ifidxes:
            t = self._vpp.sw_interface_set_l2_bridge(
                rx_sw_if_index=ifidx,
                bd_id=0,                    # no bridge id is necessary
                bvi=False,                  # BVI (no thanks)
                shg=0,                      # shared horizon group
                enable=False)              # disable bridge mode (sets l3 mode)
            self._check_retval(t)

    def ifup(self, *ifidxes):
        for ifidx in ifidxes:
            self._vpp.sw_interface_set_flags(
                sw_if_index=ifidx,
                admin_up_down=1,
                link_up_down=1,
                deleted=0)  # err, I can set the delected flag?

    def ifdown(self, *ifidxes):
        for ifidx in ifidxes:
            self._vpp.sw_interface_set_flags(
                sw_if_index=ifidx,
                admin_up_down=0,
                link_up_down=0,
                deleted=0)  # err, I can set the delected flag?
