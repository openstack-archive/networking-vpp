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


import collections
import enum
import eventlet
import fnmatch
import grp
import ipaddress
import os
import pwd
import sys
from threading import Lock
import time
import vpp_papi


L2_VTR_POP_1 = 3
L2_VTR_DISABLED = 0
NO_BVI_SET = 4294967295


def mac_to_bytes(mac):
    return str(''.join(chr(int(x, base=16)) for x in mac.split(':')))


def fix_string(s):
    return s.rstrip("\0").decode(encoding='ascii')


def bytes_to_mac(mbytes):
    return ':'.join(['%02x' % ord(x) for x in mbytes[:6]])


def bytes_to_ip(ip_bytes, is_ipv6):
    if is_ipv6:
        return str(ipaddress.ip_address(ip_bytes))
    else:
        return str(ipaddress.ip_address(ip_bytes[:4]))


def singleton(cls):
    instances = {}

    def getinstance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return getinstance


@singleton
class VPPInterface(object):

    def get_vhostusers(self):
        t = self.call_vpp('sw_interface_vhost_user_dump')

        for interface in t:
            yield (fix_string(interface.interface_name), interface)

    def is_vhostuser(self, iface_idx):
        for vhost in self.get_vhostusers():
            if vhost.sw_if_index == iface_idx:
                return True
        return False

    def get_interfaces(self):
        t = self.call_vpp('sw_interface_dump')

        for iface in t:
            mac = bytearray(iface.l2_address[:iface.l2_address_length])
            yield {'name': fix_string(iface.interface_name),
                   'tag': fix_string(iface.tag),
                   'mac': ':'.join(["%02x" % int(c) for c in mac]),
                   'sw_if_idx': iface.sw_if_index,
                   'sup_sw_if_idx': iface.sup_sw_if_index
                   }

    def get_ifidx_by_name(self, name):
        for iface in self.get_interfaces():
            if iface['name'] == name:
                return iface['sw_if_idx']
        return None

    def get_ifidx_by_tag(self, tag):
        for iface in self.get_interfaces():
            if iface['tag'] == tag:
                return iface['sw_if_idx']
        return None

    def set_interface_tag(self, if_idx, tag):
        """Define interface tag field.

        VPP papi does not allow to set interface tag
        on interface creation for subinterface or loopback).
        """
        # TODO(ijw): this is a race condition.
        self.call_vpp('sw_interface_tag_add_del',
                      is_add=1,
                      sw_if_index=if_idx,
                      tag=str(tag))

    def get_version(self):
        t = self.call_vpp('show_version')

        return fix_string(t.version)

    ########################################

    def create_tap(self, ifname, mac, tag):
        # (we don't like unicode in VPP hence str(ifname))
        t = self.call_vpp('tap_connect',
                          use_random_mac=False,
                          tap_name=str(ifname),
                          mac_address=mac_to_bytes(mac),
                          renumber=False,
                          custom_dev_instance=0,
                          tag=tag)

        if t.sw_if_index >= 0:
            # TODO(ijw): This is a temporary fix to a 17.01 bug where new
            # interfaces sometimes come up with VLAN rewrites set on them.
            # It breaks atomicity of this call and it should be removed.
            self.disable_vlan_rewrite(t.sw_if_index)

        return t.sw_if_index  # will be -1 on failure (e.g. 'already exists')

    def delete_tap(self, idx):
        self.call_vpp('tap_delete',
                      sw_if_index=idx)

    def get_taps(self):
        t = self.call_vpp('sw_interface_tap_dump')
        for iface in t:
            yield {'dev_name': fix_string(iface.dev_name),
                   'sw_if_idx': iface.sw_if_index}

    def is_tap(self, iface_idx):
        for tap in self.get_taps():
            if tap['sw_if_index'] == iface_idx:
                return True
        return False

    #############################

    def create_vhostuser(self, ifpath, mac, tag,
                         qemu_user=None, qemu_group=None, is_server=False):
        t = self.call_vpp('create_vhost_user_if',
                          is_server=is_server,
                          sock_filename=str(ifpath),
                          renumber=False,
                          custom_dev_instance=0,
                          use_custom_mac=True,
                          mac_address=mac_to_bytes(mac),
                          tag=tag)

        if is_server:
            # The permission that qemu runs as.
            uid = pwd.getpwnam(qemu_user).pw_uid
            gid = grp.getgrnam(qemu_group).gr_gid
            os.chown(ifpath, uid, gid)
            os.chmod(ifpath, 0o770)

        if t.sw_if_index >= 0:
            # TODO(ijw): This is a temporary fix to a 17.01 bug where new
            # interfaces sometimes come up with VLAN rewrites set on them.
            # It breaks atomicity of this call and it should be removed.
            self.disable_vlan_rewrite(t.sw_if_index)

        return t.sw_if_index

    def delete_vhostuser(self, idx):
        self.call_vpp('delete_vhost_user_if',
                      sw_if_index=idx)

    ########################################

    def __init__(self, log, vpp_cmd_queue_len=None):
        self.LOG = log
        jsonfiles = []
        for root, dirnames, filenames in os.walk('/usr/share/vpp/api/'):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                jsonfiles.append(os.path.join(root, filename))

        self._vpp = vpp_papi.VPP(jsonfiles)

        # Sometimes a callback fires unexpectedly.  We need to catch them
        # because vpp_papi will traceback otherwise
        self._vpp.register_event_callback(self._queue_cb)

        self.registered_callbacks = {}
        for event in self.CallbackEvents:
            self.registered_callbacks[event] = []

        # NB: a real threading lock
        self.event_q_lock = Lock()
        self.event_q = []

        if vpp_cmd_queue_len is not None:
            self._vpp.connect("python-VPPInterface",
                              rx_qlen=vpp_cmd_queue_len)
        else:
            self._vpp.connect("python-VPPInterface")

        eventlet.spawn_n(self.vpp_watcher_thread)

    def call_vpp(self, func, *args, **kwargs):
        # Disabling to prevent message debug flooding
        # self.LOG.debug('VPP: %s(%s, %s): ',
        # func, ', '.join(args), str(kwargs))
        func_call = getattr(self._vpp, func)
        try:
            t = func_call(*args, **kwargs)
        except IOError as e:
            self.LOG.exception(e)

            # We cannot guarantee the state of VPP at this point
            # and our best option is to exit.
            sys.exit(1)

        # Turning this on produces a continuous sequence of debug messages
        # self.LOG.debug('VPP: %s returned %s', func, str(t))

        # Many - but not all - return values have a 'retval'
        # flag that we can make use of to confirm success.
        # This isn't possible with multivalue calls, though.
        if getattr(t, 'retval', 0) != 0:
            self.LOG.critical('Failed VPP call to %(func)s(%(f_args)s, '
                              '%(f_kwargs)s): retval is %(rv)s',
                              {'func': func,
                               'f_args': ','.join(args),
                               'f_kwargs': kwargs,
                               'rv': t.retval})
            sys.exit(1)

        return t

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

    # Make a static lookup of message type -> event type
    callback_lookup = {}
    for event in CallbackEvents:
        (unused, event_msg_name) = event.value
        callback_lookup[event_msg_name] = event

    def _queue_cb(self, msg_name, data):
        """Queue a received callback

        This is used from the callback of VPP.  In the callback,
        the VPP library holds a lock on the response queue from
        the VPP binary, and pretty much prevents anything else
        from proceeding.  It's important that we get out of the
        way as soon as possible and absolutely don't process
        any VPP calls in the callback, so we queue the
        message for later processing and return immediately.

        NB: This is called in a Python thread and not an eventlet
        thread - it is critical that event_q_lock is *not*
        monkeypatched, as the eventlet version won't be able
        to schedule another greenthread if it blocks.
        """

        with self.event_q_lock:
            self.event_q.append((msg_name, data,))

    def _fire_cb(self, msg_name, data):
        """VPP callback.

        Fires event listeners registered with this class for
        the type of event received.

        This is called directly by VPP and indirectly by the
        background watcher thread.

        - msg_name: name of the message type
        - data: the data within the message
        """
        event = self.callback_lookup.get(msg_name)
        # Ignore unknown callbacks
        if event is not None:
            for callback in self.registered_callbacks[event]:
                callback(data)

    def register_for_events(self, event, target):
        if target in self.registered_callbacks[event]:
            raise Exception(_('Target {1} already registered for Event {2}'),
                            str(target), str(event))
        self.registered_callbacks[event].append(target)
        if len(self.registered_callbacks[event]) == 1:
            (method_name, event_cls) = event.value
            if method_name is not None:
                self.call_vpp(method_name, enable_disable=1, pid=os.getpid())

    def unregister_for_event(self, event, target):
        if target not in self.registered_callbacks[event]:
            raise Exception(_('Target {1} not registered for Event {2}'),
                            str(target), str(event))
        self.registered_callbacks[event].remove(target)
        if len(self.registered_callbacks[event]) == 0:
            (method_name, event_cls) = event.value
            if method_name is not None:
                self.call_vpp(method_name, enable_disable=0, pid=os.getpid())

    def vpp_watcher_thread(self):
        """Background thread to watch for significant changes in VPP

        Watches data and fires off 'events' - like VPP's own events - to
        users of this VPP class.  Ideally we would get VPP events
        from this, and the code is designed to make it easy to convert
        should such events become available, but right now some events
        we want - specifically, 'has the vhostuser interface connected' -
        are not sent asynchronously and we have to fake it.
        """
        prev_seen = set()
        while True:
            ifs = {}
            try:
                active = False

                # Spot vhostuser changes, specifically
                for name, data in self.get_vhostusers():
                    if data.sock_errno == 0:  # connected, near as we can tell
                        ifs[data.sw_if_index] = data
                seen = set(ifs.keys())

                newly_seen = seen - prev_seen
                for f in newly_seen:
                    self._fire_cb('XXXvhost_user_connect', ifs[f])
                    active = True
                prev_seen = seen

                # See if anything is queued
                events = []
                with self.event_q_lock:
                    events = self.event_q
                    self.event_q = []

                for (t, data) in events:
                    self._fire_cb(t, data)
                    active = True

                if not active:
                    # No change - we assume we've entered a period of
                    # nothing much happening and pause before rechecking
                    time.sleep(1)
            except Exception:
                self.LOG.exception('Exception in vpp watcher thread')

    ########################################

    def disconnect(self):
        self.call_vpp('disconnect')

    def create_bridge_domain(self, id, mac_age):
        self.call_vpp(
            'bridge_domain_add_del',
            bd_id=id,  # the numeric ID of this domain
            flood=True,  # enable bcast and mcast flooding
            uu_flood=True,  # enable unknown ucast flooding
            forward=True,  # enable forwarding on all interfaces
            learn=True,  # enable learning on all interfaces
            arp_term=False,  # enable ARP termination in the BD
            mac_age=mac_age,  # set bridge domain MAC aging TTL
            is_add=True  # is an add
        )

    def delete_bridge_domain(self, id):
        self.call_vpp(
            'bridge_domain_add_del',
            bd_id=id,  # the numeric ID of this domain
            flood=True,  # enable bcast and mcast flooding
            uu_flood=True,  # enable unknown ucast flooding
            forward=True,  # enable forwarding on all interfaces
            learn=True,  # enable learning on all interfaces
            arp_term=False,  # enable ARP termination in the BD
            is_add=False  # is a delete
        )

    def get_ifaces_in_bridge_domains(self):
        """Read current bridge configuration in VPP.

        - returns a dict
          key: bridge id
          values: array of connected sw_if_index
        """
        t = self.call_vpp('bridge_domain_dump',
                          bd_id=0xffffffff)

        # With the old API, this method returns an array containing
        # 2 types of object:
        # - bridge_domain_details
        # - bridge_domain_sw_if_details
        # With the new API, this method returns just
        # bridge_domain_details, but that
        # object now has an array of details on it.

        bridges = collections.defaultdict(list)
        for bd_info in t:
            if bd_info.__class__.__name__.endswith('sw_if_details'):
                # with the old semantics, add found indexes.
                # For new ones, no objects of this type are returned
                bridges[bd_info.bd_id].append(bd_info.sw_if_index)
            else:
                # Deal with new API semantics, and create an empty array
                # with the old
                bridges[bd_info.bd_id] = [
                    x.sw_if_index
                    for x in getattr(bd_info, 'sw_if_details', [])]
        return bridges

    def get_ifaces_in_bridge_domain(self, bd_id):
        return self.get_ifaces_in_bridge_domains().get(bd_id, [])

    def create_vlan_subif(self, if_id, vlan_tag):
        t = self.call_vpp('create_vlan_subif',
                          sw_if_index=if_id,
                          vlan_id=vlan_tag)

        # pop vlan tag from subinterface
        self.set_vlan_remove(t.sw_if_index)

        return t.sw_if_index

    def get_vlan_subif(self, if_name, seg_id):
        # We know how VPP makes names up so we can do this
        return self.get_ifidx_by_name('%s.%s' % (if_name, seg_id))

    def delete_vlan_subif(self, sw_if_index):
        self.call_vpp('delete_subif',
                      sw_if_index=sw_if_index)

    def acl_add_replace(self, acl_index, tag, rules, count):
        t = self.call_vpp('acl_add_replace',
                          acl_index=acl_index,
                          tag=str(tag),
                          r=rules,
                          count=count)
        return t.acl_index

    def macip_acl_add(self, rules, count):
        t = self.call_vpp('macip_acl_add',
                          count=count,
                          r=rules)
        return t.acl_index

    def set_acl_list_on_interface(self, sw_if_index, count, n_input, acls):
        self.call_vpp('acl_interface_set_acl_list',
                      sw_if_index=sw_if_index,
                      count=count,
                      n_input=n_input,
                      acls=acls)

    def delete_acl_list_on_interface(self, sw_if_index):
        self.call_vpp('acl_interface_set_acl_list',
                      sw_if_index=sw_if_index,
                      count=0,
                      n_input=0,
                      acls=[])

    def get_interface_acls(self, sw_if_index):
        t = self.call_vpp('acl_interface_list_dump',
                          sw_if_index=sw_if_index)
        # We're dumping one interface
        t = t[0]
        return t.acls[:t.n_input], t.acls[t.n_input:]

    def set_macip_acl_on_interface(self, sw_if_index, acl_index):
        self.call_vpp('macip_acl_interface_add_del',
                      is_add=1,
                      sw_if_index=sw_if_index,
                      acl_index=acl_index)

    def delete_macip_acl_on_interface(self, sw_if_index, acl_index):
        self.call_vpp('macip_acl_interface_add_del',
                      is_add=0,  # delete
                      sw_if_index=sw_if_index,
                      acl_index=acl_index)

    def delete_macip_acl(self, acl_index):
        self.call_vpp('macip_acl_del',
                      acl_index=acl_index)

    def acl_delete(self, acl_index):
        self.call_vpp('acl_del',
                      acl_index=acl_index)

    def get_acl_tags(self):
        t = self.call_vpp('acl_dump', acl_index=0xffffffff)
        for acl in t:
            if hasattr(acl, 'acl_index'):
                yield (acl.acl_index, fix_string(acl.tag))

    def get_macip_acl_dump(self):
        t = self.call_vpp('macip_acl_interface_get')
        return t

    ########################################

    def set_vlan_remove(self, if_id):
        self.set_vlan_tag_rewrite(if_id, L2_VTR_POP_1, 0, 0, 0)

    def disable_vlan_rewrite(self, if_id):
        self.set_vlan_tag_rewrite(if_id, L2_VTR_DISABLED, 0, 0, 0)

    def set_vlan_tag_rewrite(self, if_id, vtr_op, push_dot1q, tag1, tag2):
        t = self.call_vpp('l2_interface_vlan_tag_rewrite',
                          sw_if_index=if_id,
                          vtr_op=vtr_op,
                          push_dot1q=push_dot1q,
                          tag1=tag1,
                          tag2=tag2)
        self.LOG.info("Set subinterface vlan tag pop response: %s",
                      str(t))

    def add_to_bridge(self, bridx, *ifidxes):
        for ifidx in ifidxes:
            self.call_vpp(
                'sw_interface_set_l2_bridge',
                rx_sw_if_index=ifidx, bd_id=bridx,
                bvi=False,              # BVI (no thanks)
                shg=0,                  # shared horizon group
                enable=True)            # enable bridge mode

    def delete_from_bridge(self, *ifidxes):
        for ifidx in ifidxes:
            self.call_vpp(
                'sw_interface_set_l2_bridge',
                rx_sw_if_index=ifidx,
                bd_id=0,                # no bridge id is necessary
                bvi=False,              # BVI (no thanks)
                shg=0,                  # shared horizon group
                enable=False)           # disable bridge mode (sets l3 mode)

    def ifup(self, *ifidxes):
        """Bring a list of interfaces up

        NB: NOT ATOMIC if multiple interfaces
        """
        for ifidx in ifidxes:
            self.call_vpp('sw_interface_set_flags',
                          sw_if_index=ifidx,
                          admin_up_down=1,
                          link_up_down=1,
                          deleted=0)

    def ifdown(self, *ifidxes):
        """Bring a list of interfaces down

        NB: NOT ATOMIC if multiple interfaces
        """
        for ifidx in ifidxes:
            self.call_vpp('sw_interface_set_flags',
                          sw_if_index=ifidx,
                          admin_up_down=0,
                          link_up_down=0,
                          deleted=0)

    def create_loopback(self, mac_address):
        # Create a loopback interface to act as a BVI
        mac_address = mac_to_bytes(mac_address)
        loop = self.call_vpp('create_loopback', mac_address=mac_address)
        self.ifup(loop.sw_if_index)

        return loop.sw_if_index

    def set_loopback_bridge_bvi(self, loopback, bridge_id):
        # Sets the specified loopback interface to act as  the BVI
        # for the bridge. This interface will act as a gateway and
        # terminate the VLAN.
        self.call_vpp('sw_interface_set_l2_bridge', rx_sw_if_index=loopback,
                      bd_id=bridge_id, shg=0, bvi=True, enable=True)

    def set_interface_vrf(self, if_idx, vrf_id, is_ipv6=False):
        # Set the interface's VRF to the routers's table id
        # allocated by neutron.
        self.call_vpp('sw_interface_set_table', sw_if_index=if_idx,
                      vrf_id=vrf_id, is_ipv6=is_ipv6)

    def set_interface_ip(self, if_idx, ip, prefixlen, is_ipv6=False):
        # Set the interface IP address, usually the subnet's
        # gateway IP.
        self.call_vpp('sw_interface_add_del_address',
                      sw_if_index=if_idx, is_add=True, is_ipv6=is_ipv6,
                      del_all=False, address_length=prefixlen,
                      address=ip)

    def del_interface_ip(self, if_idx, ip, prefixlen, is_ipv6=False):
        # Delete an ip address from the specified interface
        self.call_vpp('sw_interface_add_del_address',
                      sw_if_index=if_idx, is_add=False, is_ipv6=is_ipv6,
                      del_all=False, address_length=prefixlen,
                      address=ip)

    def delete_loopback(self, loopback):
        # Delete a loopback interface, this also removes it automatically
        # from the bridge that it was set as the BVI for.
        self.call_vpp('delete_loopback', sw_if_index=loopback)

    def get_bridge_bvi(self, bd_id):
        # Returns a BVI interface index for the specified bridge id
        br_details = self.call_vpp('bridge_domain_dump', bd_id=bd_id)
        if (br_details[0].bvi_sw_if_index and
                int(br_details[0].bvi_sw_if_index) != NO_BVI_SET):
            return br_details[0].bvi_sw_if_index

        return None

    def add_ip_route(self, vrf, ip_address, prefixlen, next_hop_address,
                     next_hop_sw_if_index, is_ipv6=False):
        """Adds an IP route in the VRF or exports it from another VRF.

        Checks to see if a matching route is already present in the VRF.
        If not, the route is added or exported.
        The params, ip_address and next_hop_address are integer
        representations of the IPv4 or IPv6 address. To export a
        route from another VRF, the next_hop_addesss is set to None and the
        next_hop_sw_if_index of the interface in the target VRF is provided.
        """
        if not self.route_in_vrf(vrf, ip_address, prefixlen,
                                 next_hop_address, next_hop_sw_if_index,
                                 is_ipv6):
            ip = ipaddress.ip_address(unicode(bytes_to_ip(ip_address,
                                                          is_ipv6)))
            if next_hop_address is not None:
                next_hop = ipaddress.ip_address(unicode(bytes_to_ip(
                    next_hop_address, is_ipv6)))
                self.LOG.debug('Adding route %s/%s to %s in router vrf:%s',
                               ip, prefixlen, next_hop, vrf)
                self.call_vpp('ip_add_del_route', is_add=1, table_id=vrf,
                              dst_address=ip_address,
                              dst_address_length=prefixlen,
                              next_hop_address=next_hop_address,
                              next_hop_sw_if_index=next_hop_sw_if_index,
                              is_ipv6=is_ipv6,
                              # The next_hop_via_label param is required due
                              # to a bug in the 17.07 VPP release. VPP looks
                              # for an MPLS label in the route and crashes if
                              # it cannot find one. The label value:0xfffff+1
                              # is an invalid MPLS label.
                              next_hop_via_label=0xfffff + 1)
            elif next_hop_sw_if_index:
                self.LOG.debug('Exporting route %s/%s from vrf:%s to '
                               'next_hop_swif_idx: %s',
                               ip, prefixlen, vrf, next_hop_sw_if_index)
                self.call_vpp('ip_add_del_route', is_add=1, table_id=vrf,
                              dst_address=ip_address,
                              dst_address_length=prefixlen,
                              next_hop_sw_if_index=next_hop_sw_if_index,
                              is_ipv6=is_ipv6,
                              next_hop_via_label=0xfffff + 1)

    def delete_ip_route(self, vrf, ip_address, prefixlen, next_hop_address,
                        next_hop_sw_if_index, is_ipv6=False):
        """Deleted an IP route in the VRF.

        Checks to see if a matching route is present in the VRF.
        If present, the route is deleted.
        The params, ip_address and next_hop_address are integer
        representations of the IPv4 or IPv6 address.
        """
        if self.route_in_vrf(vrf, ip_address, prefixlen,
                             next_hop_address, next_hop_sw_if_index,
                             is_ipv6):
            ip = ipaddress.ip_address(unicode(bytes_to_ip(ip_address,
                                                          is_ipv6)))
            if next_hop_address is not None:
                next_hop = ipaddress.ip_address(unicode(bytes_to_ip(
                    next_hop_address, is_ipv6)))
                self.LOG.debug('Deleting route %s/%s to %s in router vrf:%s',
                               ip, prefixlen, next_hop, vrf)
                self.call_vpp('ip_add_del_route', is_add=0, table_id=vrf,
                              dst_address=ip_address,
                              dst_address_length=prefixlen,
                              next_hop_address=next_hop_address,
                              next_hop_sw_if_index=next_hop_sw_if_index,
                              is_ipv6=is_ipv6,
                              next_hop_via_label=0xfffff + 1)
            elif next_hop_sw_if_index:
                self.LOG.debug('Deleting exported net:%s/%s in router '
                               'vrf:%s to next_hop_swif_idx: %s',
                               ip, prefixlen, vrf, next_hop_sw_if_index)
                self.call_vpp('ip_add_del_route', is_add=0, table_id=vrf,
                              dst_address=ip_address,
                              dst_address_length=prefixlen,
                              next_hop_sw_if_index=next_hop_sw_if_index,
                              is_ipv6=is_ipv6,
                              next_hop_via_label=0xfffff + 1)

    def route_in_vrf(self, vrf, ip_address, prefixlen,
                     next_hop_address, sw_if_index, is_ipv6=False):
        """Returns True, if the route if present in the VRF.

        Pulls the VPP FIB to see if the route is present in the VRF.
        The route is identified by the tuple,
        (ip_address, prefixlen, next_hop_address)
        If the route is present, returns True or else returns False.
        The params: ip_address and next_hop_address are integer
        representations of the IPv4 or Ipv6 address.
        """
        if not is_ipv6:
            routes = self.call_vpp('ip_fib_dump')
        else:
            routes = self.call_vpp('ip6_fib_dump')
        # Iterate though the routes and check for a matching route tuple
        # in the VRF table by checking the ip_address, prefixlen and
        # Convert the ip & next_hop addresses to an ipaddress format for
        # comparison
        ip = ipaddress.ip_address(unicode(bytes_to_ip(ip_address,
                                                      is_ipv6)))
        if next_hop_address is not None:
            next_hop = ipaddress.ip_address(unicode(
                bytes_to_ip(next_hop_address, is_ipv6)))
        else:
            next_hop = next_hop_address

        for route in routes:
            # if there's a valid next_hop_address check for the route by
            # including it
            if (next_hop_address and route.table_id == vrf and
                route.address_length == prefixlen and
                # check if route.address == ip
                ipaddress.ip_address(
                    unicode(bytes_to_ip(route.address,
                                        is_ipv6))) == ip and
                # check if the next_hop is present the list
                # of next hops in the route's path
                next_hop in [ipaddress.ip_address(
                    unicode(bytes_to_ip(p.next_hop,
                                        is_ipv6))) for p in route.path]):
                self.LOG.debug('Route: %s/%s to %s exists in VRF:%s',
                               ip, prefixlen, next_hop, vrf)
                return True
            elif (sw_if_index and route.table_id == vrf and
                  route.address_length == prefixlen and
                  # check if route.address == ip
                  ipaddress.ip_address(
                      unicode(bytes_to_ip(route.address,
                                          is_ipv6))) == ip and
                  # check if the next_hop matches
                  sw_if_index in [p.sw_if_index for p in route.path]):

                self.LOG.debug('Route: %s/%s to sw_if_idx:%s is imported '
                               'into VRF:%s', ip, prefixlen, sw_if_index,
                               vrf)
                return True
            # Note: The else clause in 'for' loop is executed when the
            # loop terminates without finding a matching route
        else:
            self.LOG.debug('Route: %s/%s to %s does not exist in VRF:%s',
                           ip, prefixlen, next_hop, vrf)
            return False

    def get_interface_ip_addresses(self, sw_if_idx):
        """Returns a list of all IP addresses assigned to an interface.

        This will return both v4 and v6 adressess in a list of tuples
        that contains the ip address and subnet mask. e.g.
        [(10.0.0.1, 24), (2001:db8:1234::1, 64)]
        """
        int_addrs = []
        v4_addrs = self.call_vpp('ip_address_dump', sw_if_index=sw_if_idx,
                                 is_ipv6=False)
        for v4_addr in v4_addrs:
            # Only count the first 4 bytes for v4 addresses
            sanitized_v4 = v4_addr[3][:4]
            int_addrs.append((str(ipaddress.ip_address(sanitized_v4).exploded),
                             v4_addr[4]))

        v6_addrs = self.call_vpp('ip_address_dump', sw_if_index=sw_if_idx,
                                 is_ipv6=True)
        for v6_addr in v6_addrs:
            int_addrs.append((str(ipaddress.ip_address(v6_addr[3]).exploded),
                             v6_addr[4]))
        return int_addrs

    def set_interface_mtu(self, sw_if_idx, mtu):
        self.call_vpp('sw_interface_set_mtu', sw_if_index=sw_if_idx, mtu=mtu)

    def set_snat_on_interface(self, sw_if_index, is_inside=1, is_add=1):
        self.call_vpp('snat_interface_add_del_feature',
                      sw_if_index=sw_if_index,
                      is_inside=is_inside,
                      is_add=is_add)

    # Adds an SNAT address to the pool
    def add_del_snat_address(self, ip_addr, vrf_id, is_add=True):
        self.call_vpp('snat_add_address_range', first_ip_address=ip_addr,
                      last_ip_address=ip_addr, vrf_id=vrf_id, is_add=is_add,
                      is_ip4=True)

    # 1:N overload on the IP address assigned to the interface
    def snat_overload_on_interface_address(self, sw_if_index, is_add=1):
        """Sets/Removes 1:N NAT overload on the outside interface address."""
        self.call_vpp('snat_add_del_interface_addr',
                      is_add=is_add, is_inside=0, sw_if_index=sw_if_index)

    def get_outside_snat_interface_indices(self):
        """Returns the sw_if_indices of interfaces with 1:N NAT enabled"""
        return [intfs.sw_if_index
                for intfs in self.call_vpp('snat_interface_addr_dump')]

    def get_snat_interfaces(self):
        snat_interface_list = []
        snat_interfaces = self.call_vpp('snat_interface_dump')
        for intf in snat_interfaces:
            snat_interface_list.append(intf.sw_if_index)
        return snat_interface_list

    def get_snat_local_ipaddresses(self):
        # NB: Only IPv4 SNAT addresses are supported.
        snat_local_ipaddresses = []
        snat_static_mappings = self.call_vpp('snat_static_mapping_dump')
        for static_mapping in snat_static_mappings:
            snat_local_ipaddresses.append(
                str(ipaddress.IPv4Address(
                    static_mapping.local_ip_address[:4])))
        return snat_local_ipaddresses

    def get_snat_static_mappings(self):
        return self.call_vpp('snat_static_mapping_dump')

    def set_snat_static_mapping(self, local_ip, external_ip, is_add=1):
        local_ip = str(ipaddress.IPv4Address(local_ip).packed)
        external_ip = str(ipaddress.IPv4Address(external_ip).packed)
        self.call_vpp('snat_add_static_mapping',
                      local_ip_address=local_ip,
                      external_ip_address=external_ip,
                      external_sw_if_index=0xFFFFFFFF,  # -1 = Not used
                      local_port=0,     # 0 = ignore
                      external_port=0,  # 0 = ignore
                      addr_only=1,      # 1 = address only mapping
                      vrf_id=0,         # 0 = global VRF
                      is_add=is_add,    # 1 = add, 0 = delete
                      is_ip4=1)         # 1 = address type is IPv4

    def get_snat_addresses(self):
        ret_addrs = []
        addresses = self.call_vpp('snat_address_dump')
        for addr in addresses:
            ret_addrs.append(str(ipaddress.ip_address(addr[3][:4]).exploded))

        return ret_addrs

    def get_bridge_domains(self):
        t = self.call_vpp('bridge_domain_dump', bd_id=0xffffffff)
        return set([bd.bd_id for bd in t])

    def lisp_enable(self):
        self.call_vpp('lisp_enable_disable', is_en=1)

    def is_lisp_enabled(self):
        t = self.call_vpp('show_lisp_status')
        return t.gpe_status

    def get_lisp_vni_to_bd_mappings(self):
        """Retrieve LISP mappings between the VNI and Bridge Domain."""
        t = self.call_vpp('lisp_eid_table_map_dump', is_l2=1)
        return [(eid_map.vni, eid_map.dp_table) for eid_map in t]

    def add_lisp_vni_to_bd_mapping(self, vni, bridge_domain):
        """Add a LISP mapping between a VNI and bridge-domain."""
        self.call_vpp('lisp_eid_table_add_del_map',
                      is_add=1,
                      vni=vni,
                      dp_table=bridge_domain,
                      is_l2=1)

    def del_lisp_vni_to_bd_mapping(self, vni, bridge_domain):
        """Delete the LISP mapping between a VNI and bridge-domain."""
        self.call_vpp('lisp_eid_table_add_del_map',
                      is_add=0,
                      vni=vni,
                      dp_table=bridge_domain,
                      is_l2=1)

    def set_interface_address(self, sw_if_index, is_ipv6,
                              address_length, address):
        """Configure an IPv4 or IPv6 address on a software interface."""
        self.call_vpp('sw_interface_add_del_address',
                      sw_if_index=sw_if_index,
                      is_add=1,
                      is_ipv6=is_ipv6,
                      del_all=False,
                      address_length=address_length,
                      address=address)

    def del_interface_address(self, sw_if_index, is_ipv6,
                              address_length, address):
        """Remove an IPv4 or IPv6 address on a software interface."""
        self.call_vpp('sw_interface_add_del_address',
                      sw_if_index=sw_if_index,
                      is_add=0,
                      is_ipv6=is_ipv6,
                      del_all=False,
                      address_length=address_length,
                      address=address)

    def add_lisp_local_mac(self, mac, vni, locator_set_name):
        """Add a local mac address to VNI association in LISP"""
        self.call_vpp('lisp_add_del_local_eid',
                      is_add=1,
                      eid_type=2,  # 2: mac_address
                      eid=mac_to_bytes(mac),
                      prefix_len=0,
                      locator_set_name=locator_set_name,
                      vni=vni)

    def del_lisp_local_mac(self, mac, vni, locator_set_name):
        """Delete a local mac address to VNI association in LISP"""
        self.call_vpp('lisp_add_del_local_eid',
                      is_add=0,
                      eid_type=2,  # type 2: mac_address
                      eid=mac_to_bytes(mac),
                      prefix_len=0,
                      locator_set_name=locator_set_name,
                      vni=vni)

    def add_lisp_remote_mac(self, mac, vni, underlay):
        """Add a LISP entry for a remote mac address to the underlay IP.

        Arguments:-
        mac - remote mac_address
        vni - virtual network identifier
        underlay - An underlay IP represented within a dict. as below:
                           {"is_ip4": <value>,
                           "priority": <priority>,
                           "weight": <weight>,
                           "addr": <binary IPv4 or IPv6 address>}])
        """
        self.call_vpp('lisp_add_del_remote_mapping',
                      is_add=1,
                      vni=vni,
                      eid_type=2,  # type 2: mac_address
                      eid=mac_to_bytes(mac),
                      rlocs=[underlay],
                      rloc_num=1,
                      is_src_dst=0)

    def del_lisp_remote_mac(self, mac, vni):
        """Delete a LISP entry for a remote mac address.

        Arguments:-
        mac - remote mac_address
        vni - virtual network identifier
        """
        self.call_vpp('lisp_add_del_remote_mapping',
                      is_add=0,
                      vni=vni,
                      eid_type=2,  # type 2: mac_address
                      eid=mac_to_bytes(mac),
                      rlocs=[],
                      rloc_num=0,
                      is_src_dst=0)

    def add_lisp_locator_set(self, locator_set_name):
        """Adds a LISP locator set.

        A LISP locator set is a set of underlay interfaces used by GPE.
        """
        t = self.call_vpp('lisp_add_del_locator_set',
                          is_add=1,
                          locator_set_name=locator_set_name,
                          locator_num=0,
                          locators=[])
        return t.ls_index

    def add_lisp_locator(self, locator_set_name, sw_if_index,
                         priority=1, weight=1):
        """Adds a LISP locator to the locator set.

        A LISP locator is the software interface index of the underlay
        interface.
        """
        self.call_vpp('lisp_add_del_locator',
                      is_add=1,
                      locator_set_name=locator_set_name,
                      sw_if_index=sw_if_index,
                      priority=priority,
                      weight=weight)

    def del_lisp_locator(self, locator_set_name, sw_if_index):
        """Removes a LISP locator from the locator set.

        A LISP locator is the software interface index of the underlay
        interface.
        """
        self.call_vpp('lisp_add_del_locator',
                      is_add=0,
                      locator_set_name=locator_set_name,
                      sw_if_index=sw_if_index)

    def add_lisp_arp_entry(self, mac, bridge_domain, ipv4_address):
        """Adds a static ARP entry to LISP.

        ipv4_address is an integer representation of the IPv4 address.
        """
        self.call_vpp('one_add_del_l2_arp_entry',
                      is_add=1,
                      mac=mac_to_bytes(mac),
                      bd=bridge_domain,
                      ip4=ipv4_address
                      )

    def del_lisp_arp_entry(self, mac, bridge_domain, ipv4_address):
        """Removes a static ARP entry from LISP.

        ipv4_address is an integer representation of the IPv4 address.
        """
        self.call_vpp('one_add_del_l2_arp_entry',
                      is_add=0,
                      mac=mac_to_bytes(mac),
                      bd=bridge_domain,
                      ip4=ipv4_address
                      )

    def replace_lisp_arp_entry(self, mac, bridge_domain, ipv4_address):
        """Replaces the LISP ARP entry in a bridge domain for the IP address.

        ipv4_adddress is an integer representation of the IPv4 address.
        """
        # Delete the current ARP entry for the ipv4_address in the BD
        for mac_addr, ip4 in [(arp.mac, arp.ip4) for arp in
                              self.call_vpp('one_l2_arp_entries_get',
                                            bd=bridge_domain).entries
                              if arp.ip4 == ipv4_address]:
            self.call_vpp('one_add_del_l2_arp_entry',
                          is_add=0, mac=mac_addr, bd=bridge_domain, ip4=ip4)
        # Add the new ARP entry
        self.add_lisp_arp_entry(mac, bridge_domain, ipv4_address)

    def exists_lisp_arp_entry(self, bridge_domain, ipv4_address):
        """Return True if a LISP ARP entry exists in the bridge_domain.

        ipv4_address is an integer representation of the IPv4 address.
        """
        return ipv4_address in [arp.ip4 for arp in
                                self.call_vpp('one_l2_arp_entries_get',
                                              bd=bridge_domain).entries]

    def clear_lisp_arp_entries(self, bridge_domain):
        """Clear LISP ARP entries in the bridge_domain."""
        for mac, ip4 in [(arp.mac, arp.ip4) for arp in
                         self.call_vpp('one_l2_arp_entries_get',
                                       bd=bridge_domain).entries]:
            self.call_vpp('one_add_del_l2_arp_entry',
                          is_add=0, mac=mac, bd=bridge_domain, ip4=ip4)

    def get_lisp_local_locators(self, name):
        """Get lisp local locator sets and their corresponding locators.

        GPE uses a locator-set to group the available underlay interfaces.
        Each underlay interface is called a locator. This method is used to
        retrieve the list of locators present within VPP for a certain
        locator-set.

        Arguments:-
        name: The name of the locator set

        Returns:-
        A list of locators.
        Each locator is a dictionary and has as key named "sw_if_idxs" used
        to identify all the software indexes within VPP functioning as the
        underlay interfaces for the locator set.

        """
        locators = []
        # filter=1 for local locators
        t = self.call_vpp('lisp_locator_set_dump', filter=1)
        for ls in t:
            ls_set_name = fix_string(ls.ls_name)
            if ls_set_name == name:
                locators.append({'locator_set_name': ls_set_name,
                                 'locator_set_index': ls.ls_index,
                                 'sw_if_idxs': [intf.sw_if_index for
                                                intf in self.call_vpp(
                                                    'lisp_locator_dump',
                                                    ls_name=str(ls_set_name))
                                                ]
                                 }
                                )
        return locators

    def get_lisp_locator_ip(self, locator_index):
        """Get the IP address of the locator (i.e. underlay) from its index"""
        t = self.call_vpp('lisp_locator_dump',
                          ls_index=locator_index,
                          is_index_set=1)
        for locator in t:
            return bytes_to_ip(locator.ip_address, locator.is_ipv6)

    def get_lisp_eid_table(self):
        """Query the LISP EID table within VPP and return its contents.

        A LISP EID table keeps a mapping between the mac-addresses, VNI
        and the underlay interfaces known to VPP. The 'is_local' key
        is used to determine whether the mapping is local or remote.
        """
        t = self.call_vpp('lisp_eid_table_dump')
        return [{'is_local': val.is_local,
                 'locator_set_index': val.locator_set_index,
                 'mac': bytes_to_mac(val.eid),
                 'vni': val.vni
                 }
                for val in t]
