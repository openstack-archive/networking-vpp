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


import collections
import enum
import eventlet
from eventlet import semaphore
import fnmatch
import grp
import os
import pwd
import time
import vpp_papi

L2_VTR_POP_1 = 3


def mac_to_bytes(mac):
    return str(''.join(chr(int(x, base=16)) for x in mac.split(':')))


def fix_string(s):
    return s.rstrip("\0").decode(encoding='ascii')


def singleton(cls):
    instances = {}

    def getinstance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return getinstance


@singleton
class VPPInterface(object):

    def _check_retval(self, t):
        """See if VPP returned OK.

        VPP is very inconsistent in return codes, so for now this reports
        a logged warning rather than flagging an error.
        """

        try:
            self.LOG.debug("checking return value for object: %s", str(t))
            if t.retval != 0:
                self.LOG.debug('FAIL? retval here is %s', t.retval)
        except AttributeError as e:
            self.LOG.debug("Unexpected request format.  Error: %s on %s"
                           % (e, t))

    def get_vhostusers(self):
        t = self._vpp.sw_interface_vhost_user_dump()

        for interface in t:
            yield (fix_string(interface.interface_name), interface)

    def is_vhostuser(self, iface_idx):
        for vhost in self.get_vhostusers():
            if vhost.sw_if_index == iface_idx:
                return True
        return False

    def get_interfaces(self):
        t = self._vpp.sw_interface_dump()

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
        t = self._vpp.sw_interface_tag_add_del(is_add=1,
                                               sw_if_index=if_idx,
                                               tag=str(tag))
        self._check_retval(t)

    def get_version(self):
        t = self._vpp.show_version()

        self._check_retval(t)

        return fix_string(t.version)

    ########################################

    def create_tap(self, ifname, mac, tag):
        # (we don't like unicode in VPP hence str(ifname))
        t = self._vpp.tap_connect(use_random_mac=False,
                                  tap_name=str(ifname),
                                  mac_address=mac_to_bytes(mac),
                                  renumber=False,
                                  custom_dev_instance=0,
                                  tag=tag)

        self._check_retval(t)

        return t.sw_if_index  # will be -1 on failure (e.g. 'already exists')

    def delete_tap(self, idx):
        self._vpp.tap_delete(sw_if_index=idx)

        # Err, I just got a sw_interface_set_flags here, not a delete tap?
        # self._check_retval(t)

    def get_taps(self):
        t = self._vpp.sw_interface_tap_dump()
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
        self.LOG.debug('Creating %s as a port', ifpath)

        t = self._vpp.create_vhost_user_if(is_server=is_server,
                                           sock_filename=str(ifpath),
                                           renumber=False,
                                           custom_dev_instance=0,
                                           use_custom_mac=True,
                                           mac_address=mac_to_bytes(mac),
                                           tag=tag)

        self.LOG.debug("Created vhost user interface object: %s", str(t))
        self._check_retval(t)

        if is_server:
            # The permission that qemu runs as.
            self.LOG.debug(('Changing vhostuser interface file permission '
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

        self.event_q_lock = semaphore.Semaphore()
        self.event_q = []

        if vpp_cmd_queue_len is not None:
            self._vpp.connect("python-VPPInterface",
                              rx_qlen=vpp_cmd_queue_len)
        else:
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

        TODO(ijw): this may still leave the possibility that
        the thread yields.  If so, we need to request a change
        from the VPP team.
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
        self._vpp.disconnect()

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

    def get_ifaces_in_bridge_domains(self):
        """Read current bridge configuration in VPP.

        - returns a dict
          key: bridge id
          values: array of connected sw_if_index
        """
        t = self._vpp.bridge_domain_dump(bd_id=0xffffffff)
        # this method returns an array containing 2 types of object:
        # - bridge_domain_details
        # - bridge_domain_sw_if_details
        # build a dict containing: {bridge_id--> list of interfaces}

        bridges = collections.defaultdict(list)
        for bd_info in t:
            if bd_info.__class__.__name__.endswith('sw_if_details'):
                bridges[bd_info.bd_id].append(bd_info.sw_if_index)
            else:
                # extending with an empty array is harmless but this ensures
                # the key (ie: bridge_id) exists
                bridges[bd_info.bd_id].extend([])
        return bridges

    def get_ifaces_in_bridge_domain(self, bd_id):
        return self.get_ifaces_in_bridge_domains().get(bd_id, [])

    def create_vlan_subif(self, if_id, vlan_tag):
        self.LOG.debug("Creating vlan subinterface with ID:%s and vlan_tag:%s"
                       % (if_id, vlan_tag))
        t = self._vpp.create_vlan_subif(
            sw_if_index=if_id,
            vlan_id=vlan_tag)
        self.LOG.debug("Create vlan subinterface response: %s", str(t))

        self._check_retval(t)

        # pop vlan tag from subinterface
        self.set_vlan_remove(t.sw_if_index)

        return t.sw_if_index

    def get_vlan_subif(self, if_name, seg_id):
        # We know how VPP makes names up so we can do this
        return self.get_ifidx_by_name('%s.%s' % (if_name, seg_id))

    def delete_vlan_subif(self, sw_if_index):
        self.LOG.debug("Deleting subinterface with sw_if_index: %s"
                       % (sw_if_index))
        t = self._vpp.delete_subif(sw_if_index=sw_if_index)
        self.LOG.debug("Delete subinterface response: %s", str(t))

        self._check_retval(t)
        return

    def acl_add_replace(self, acl_index, tag, rules, count):
        self.LOG.debug("Add_Replace vpp acl with indx %s tag %s rules %s "
                       "count %s" % (acl_index, tag, rules, count))
        t = self._vpp.acl_add_replace(acl_index=acl_index,
                                      tag=str(tag),
                                      r=rules,
                                      count=count)
        self.LOG.debug("ACL add_replace response: %s" % str(t))
        self._check_retval(t)
        return t.acl_index

    def macip_acl_add(self, rules, count):
        self.LOG.debug("Adding macip acl with rules %s count %s"
                       % (rules, count))
        t = self._vpp.macip_acl_add(count=count,
                                    r=rules)
        self.LOG.debug("macip ACL add_replace response: %s" % str(t))
        self._check_retval(t)
        return t.acl_index

    def set_acl_list_on_interface(self, sw_if_index, count, n_input, acls):
        self.LOG.debug("Setting ACL vector %s on VPP interface %s"
                       % (acls, sw_if_index))
        t = self._vpp.acl_interface_set_acl_list(sw_if_index=sw_if_index,
                                                 count=count,
                                                 n_input=n_input,
                                                 acls=acls)
        self.LOG.debug("ACL set_acl_list_on_interface response: %s" % str(t))
        self._check_retval(t)
        return t.retval  # Return 0 on success

    def delete_acl_list_on_interface(self, sw_if_index):
        self.LOG.debug("Deleting ACLs from VPP interface %s", sw_if_index)
        t = self._vpp.acl_interface_set_acl_list(sw_if_index=sw_if_index,
                                                 count=0,
                                                 n_input=0,
                                                 acls=[])
        self.LOG.debug("Delete_acl_list_on_interface response: %s", str(t))
        self._check_retval(t)

    def set_macip_acl_on_interface(self, sw_if_index, acl_index):
        self.LOG.debug("Setting macip acl %s on VPP interface %s"
                       % (acl_index, sw_if_index))
        t = self._vpp.macip_acl_interface_add_del(is_add=1,
                                                  sw_if_index=sw_if_index,
                                                  acl_index=acl_index)
        self.LOG.debug("macip ACL set_acl_list_on_interface response: %s"
                       % str(t))
        self._check_retval(t)
        return t.retval

    def delete_macip_acl_on_interface(self, sw_if_index, acl_index):
        self.LOG.debug("Deleting macip acl %s on VPP interface %s",
                       acl_index, sw_if_index)
        t = self._vpp.macip_acl_interface_add_del(is_add=0,  # delete
                                                  sw_if_index=sw_if_index,
                                                  acl_index=acl_index)
        self.LOG.debug("macip ACL delete_acl_list_on_interface response: %s",
                       str(t))
        self._check_retval(t)

    def delete_macip_acl(self, acl_index):
        self.LOG.debug("Deleting macip acl index %s" % acl_index)
        t = self._vpp.macip_acl_del(acl_index=acl_index)
        self.LOG.debug("macip ACL delete response: %s" % str(t))
        self._check_retval(t)

    def acl_delete(self, acl_index):
        self.LOG.debug("Deleting vpp acl index %s" % acl_index)
        t = self._vpp.acl_del(acl_index=acl_index)
        self.LOG.debug("ACL delete response: %s" % str(t))
        self._check_retval(t)

    def get_acl_tags(self):
        self.LOG.debug("Getting the ACL dump")
        t = self._vpp.acl_dump(acl_index=0xffffffff)
        self.LOG.debug("ACL dump response: %s" % str(t))
        for acl in t:
            if hasattr(acl, 'acl_index'):
                yield (acl.acl_index, fix_string(acl.tag))

    def get_macip_acl_dump(self):
        self.LOG.debug("Getting the MAC-IP Interface ACL dump")
        t = self._vpp.macip_acl_interface_get()
        self.LOG.debug("MAC-IP ACL dump response: %s" % str(t))
        return t

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
        self.LOG.info("Set subinterface vlan tag pop response: %s", str(t))

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
