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
import grp
import os
import pwd
import vpp_papi

L2_VTR_POP_1 = 3


def mac_to_bytes(mac):
    return str(''.join(chr(int(x, base=16)) for x in mac.split(':')))


def fix_string(s):
    return s.rstrip("\0").decode(encoding='ascii')


def _cb(*args, **kwargs):
    # Forward callback to VPPInterface instance
    # we can pass None as the logger, as we're accessing
    # to a singleton, and we can't be called before the
    # real initialization of VPPInterface.
    VPPInterface(None)._cb(args, kwargs)


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

    def get_interfaces(self):
        t = vpp_papi.sw_interface_dump(0, b'ignored')

        for interface in t:
            if interface.vl_msg_id == vpp_papi.vpe.VL_API_SW_INTERFACE_DETAILS:
                yield (fix_string(interface.interface_name), interface)

    def get_interface(self, name):
        for (ifname, f) in self.get_interfaces():
            if ifname == name:
                return f

    def get_version(self):
        t = vpp_papi.show_version()

        self._check_retval(t)

        return fix_string(t.version)

    ########################################

    def create_tap(self, ifname, mac):
        # (we don't like unicode in VPP hence str(ifname))
        t = vpp_papi.tap_connect(False,  # random MAC
                                 str(ifname),
                                 mac_to_bytes(mac),
                                 False,  # renumber - who knows, no doc
                                 0)  # customdevinstance - who knows, no doc

        self._check_retval(t)

        return t.sw_if_index  # will be -1 on failure (e.g. 'already exists')

    def delete_tap(self, idx):
        vpp_papi.tap_delete(idx)

        # Err, I just got a sw_interface_set_flags here, not a delete tap?
        # self._check_retval(t)

    #############################

    def create_vhostuser(self, ifpath, mac,
                         qemu_user=None, qemu_group=None, is_server=False):
        self.LOG.info('Creating %s as a port', ifpath)

        t = vpp_papi.create_vhost_user_if(is_server,
                                          str(ifpath),  # unicode not allowed.
                                          False,  # Who knows what renumber is?
                                          0,  # custom_dev_instance
                                          True,  # use custom MAC
                                          mac_to_bytes(mac)
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
        t = vpp_papi.delete_vhost_user_if(idx)

        self._check_retval(t)

    ########################################
    def __init__(self, log):
        print('__init__')
        self.LOG = log
        self.r = vpp_papi.connect("test_papi")
        self.registered_callbacks = {}
        for event in self.CallbackEvents:
            self.registered_callbacks[event] = []
        vpp_papi.register_event_callback(_cb)

    ########################################
    class CallbackEvents(enum.Enum):
        INTERFACE = (vpp_papi.want_interface_events,
                     vpp_papi.vpe.sw_interface_set_flags)
        STATISTICS = (vpp_papi.want_stats,
                      vpp_papi.vpe.vnet_interface_counters)
        OAM = (vpp_papi.want_oam_events,
               vpp_papi.vpe.oam_event)

    def _cb(self, *args, **kwargs):
        # sw_interface_set_flags comes back when you delete interfaces
        # print 'callback:', args, kwargs
        for event in self.CallbackEvents:
            (method, event_cls) = event.value
            if type(args[0]) is event_cls:
                for (cb, cb_arg) in self.registered_callbacks[event]:
                    cb(cb_arg, args[0])

    def register_for_events(self, event, target, arg):
        if (target, arg) in self.registered_callbacks[event]:
            raise Exception('Target %s already registered for Event %s',
                            str(target), str(event))
        self.registered_callbacks[event].append((target, arg))
        if len(self.registered_callbacks[event]) == 1:
            (register_method, event_cls) = event.value
            register_method(1, os.getpid())

    def unregister_for_event(self, event, target, arg):
        if (target, arg) not in self.registered_callbacks[event]:
            raise Exception('Target %s not registered for Event %s',
                            str(target), str(event))
        self.registered_callbacks[event].remove((target, arg))
        if len(self.registered_callbacks[event]) == 0:
            (register_method, event_cls) = event.value
            register_method(0, os.getpid())

    ########################################

    def disconnect(self):
        vpp_papi.disconnect()

    def create_bridge_domain(self, id):
        t = vpp_papi.bridge_domain_add_del(
            id,  # the numeric ID of this domain
            True,  # enable bcast and mcast flooding
            True,  # enable unknown ucast flooding
            True,  # enable forwarding on all interfaces
            True,  # enable learning on all interfaces
            False,  # enable ARP termination in the BD
            True  # is an add
        )
        self._check_retval(t)

    def delete_bridge_domain(self, id):
        t = vpp_papi.bridge_domain_add_del(
            id,  # the numeric ID of this domain
            True,  # enable bcast and mcast flooding
            True,  # enable unknown ucast flooding
            True,  # enable forwarding on all interfaces
            True,  # enable learning on all interfaces
            False,  # enable ARP termination in the BD
            False  # is a delete
        )
        self._check_retval(t)

    def create_vlan_subif(self, if_id, vlan_tag):
        self.LOG.debug("Creating vlan subinterface with ID:%s and vlan_tag:%s"
                       % (if_id, vlan_tag))
        t = vpp_papi.create_vlan_subif(
            if_id,
            vlan_tag)
        self.LOG.debug("Create vlan subinterface response: %s", str(t))

        self._check_retval(t)

        # pop vlan tag from subinterface
        self.set_vlan_remove(t.sw_if_index)

        return t.sw_if_index

    def delete_vlan_subif(self, sw_if_index):
        self.LOG.debug("Deleting subinterface with sw_if_index: %s"
                       % (sw_if_index))
        t = vpp_papi.delete_subif(sw_if_index)
        self.LOG.debug("Delete subinterface response: %s", str(t))

        self._check_retval(t)
        return

#    def create_srcrep_vxlan_subif(self, vrf_id, src_addr, bcast_addr, vnid):
#        t = vpp_papi.vxlan_add_del_tunnel(
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
        t = vpp_papi.l2_interface_vlan_tag_rewrite(
            if_id,
            vtr_op,
            push_dot1q,
            tag1,
            tag2)
        self.LOG.info("Set subinterface vlan tag pop response: %s", str(t))

        self._check_retval(t)

    def add_to_bridge(self, bridx, *ifidxes):
        for ifidx in ifidxes:
            t = vpp_papi.sw_interface_set_l2_bridge(
                ifidx, bridx,
                False,                  # BVI (no thanks)
                0,                      # shared horizon group
                True)                   # enable bridge mode
            self._check_retval(t)

    def delete_from_bridge(self, *ifidxes):
        for ifidx in ifidxes:
            t = vpp_papi.sw_interface_set_l2_bridge(
                ifidx,
                0,                      # no bridge id is necessary
                False,                  # BVI (no thanks)
                0,                      # shared horizon group
                False)                  # disable bridge mode (sets l3 mode)
            self._check_retval(t)

    def ifup(self, *ifidxes):
        for ifidx in ifidxes:
            vpp_papi.sw_interface_set_flags(
                ifidx,
                1, 1,               # admin and link up
                0)                   # err, I can set the delected flag?

    def ifdown(self, *ifidxes):
        for ifidx in ifidxes:
            vpp_papi.sw_interface_set_flags(
                ifidx,
                0, 0,               # admin and link down
                0)                   # err, I can set the delected flag?
