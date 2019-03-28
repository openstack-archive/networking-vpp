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


from __future__ import absolute_import
from __future__ import print_function
import collections
import enum
import fnmatch
import grp
import ipaddress
# logging is included purely for typechecks and pep8 objects to its inclusion
import logging  # noqa
import os
import pwd
import six
import sys
from threading import Lock
# typing is included purely for typechecks and pep8 objects to its inclusion
from typing import List, Dict, Optional, Set, Tuple, Iterator  # noqa
import vpp_papi  # type: ignore


L2_VTR_POP_1 = 3
L2_VTR_DISABLED = 0
NO_BVI_SET = 4294967295


def binary_type(s):
    # type: (str) -> bytes
    """Wrapper function to convert input string to bytes

    TODO(onong): move to a common file in phase 2
    """
    return s.encode('ascii')


def mac_to_bytes(mac):
    # type: (str) -> six.binary_type
    # py3 note:
    # TODO(onong): PAPI has introduced a new macaddress object which seemingly
    # takes care of conversion to/from MAC addr to string.
    # TODO(onong): move to common file in phase 2
    if six.PY2:
        return ''.join(chr(int(x, base=16)) for x in mac.split(':'))
    else:
        return bytes.fromhex(mac.replace(':', ''))


def fix_string(s):
    # type: (bytes) -> str
    # py3 note:
    # This function chops off any trailing NUL chars/bytes from strings that
    # we get from VPP. Now, in case of py2, str and bytes are the same but
    # there's a strict distinction between the two in py3. The code ensures
    # that within the ML2 agent we follow the dictum of always dealing with
    # strings and this function acts as the boundary where the conversion to
    # string happens.
    #
    # TODO(onong): watch out for the upcoming PAPI change which introduces a
    # string type for printable strings, so no longer the need for the funny
    # chopping off of 0's at the end. But this function will still act as the
    # boundary at which input is converted to string type.
    # TODO(onong): move to common file in phase 2
    # This consistently returns a string in py2 and 3, and since we know
    # the input is binary ASCII we can safely make the cast in py2.
    return str(s.decode('ascii').rstrip('\0'))


def bytes_to_mac(mbytes):
    # type: (str) -> str
    return ':'.join(['%02x' % ord(x) for x in mbytes[:6]])


def bytes_to_ip(ip_bytes, is_ipv6):
    # type: (bytes, bool) -> str
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

    def get_interfaces(self):
        # type: () -> Iterator[dict]
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
        # type: (str) -> Optional[int]
        for iface in self.get_interfaces():
            if iface['name'] == name:
                return iface['sw_if_idx']
        return None

    def get_ifidx_mac_address(self, ifidx):
        # type: (int) -> Optional[bytes]

        for iface in self.get_interfaces():
            if iface['sw_if_idx'] == ifidx:
                return iface['mac']
        return None

    def get_ifidx_by_tag(self, tag):
        # type: (str) -> Optional[int]
        for iface in self.get_interfaces():
            if iface['tag'] == tag:
                return iface['sw_if_idx']
        return None

    def set_interface_tag(self, if_idx, tag):
        # type: (int, str) -> None
        """Define interface tag field.

        VPP papi does not allow to set interface tag
        on interface creation for subinterface or loopback).
        """
        # TODO(ijw): this is a race condition - we should create the
        # interface with a tag.
        self.call_vpp('sw_interface_tag_add_del',
                      is_add=1,
                      sw_if_index=if_idx,
                      tag=binary_type(tag))

    def get_version(self):
        # type: () -> str
        t = self.call_vpp('show_version')

        return t.version

    def semver(self):
        # type: () -> Tuple[int, int, bool]
        """Return the 'semantic' version components of a VPP version"""

        # version string is in the form yy.mm{cruft}*
        # the cruft is there if it's an interstitial version during
        # the dev cycle, and note that these versions may have a
        # changed and unpredictable API.
        version_string = self.get_version()
        yy = int(version_string[:2])
        mm = int(version_string[3:5])
        plus = len(version_string[5:]) != 0

        return (yy, mm, plus)

    def ver_ge(self, tyy, tmm):
        # type: (int, int) -> bool
        (yy, mm, plus) = self.semver()
        if tyy < yy:
            return True
        elif tyy == yy and tmm <= mm:
            return True
        else:
            return False

    ########################################

    def create_tap(self, ifname, mac=None, tag=""):
        # type: (str, str, str) -> int
        if mac is not None:
            mac_bytes = mac_to_bytes(mac)
            use_random_mac = False
        else:
            mac_bytes = mac_to_bytes('00:00:00:00:00:00')
            use_random_mac = True

        t = self.call_vpp('tap_create_v2',
                          use_random_mac=use_random_mac,
                          mac_address=mac_bytes,
                          host_if_name_set=True,
                          host_if_name=binary_type(ifname),
                          id=0xffffffff,  # choose ifidx automatically
                          host_ip4_addr_set=False,
                          host_ip6_addr_set=False,
                          host_bridge_set=False,
                          host_namespace_set=False,
                          host_mac_addr_set=False,
                          tx_ring_sz=1024,
                          rx_ring_sz=1024,
                          tag=binary_type(tag))

        return t.sw_if_index  # will be -1 on failure (e.g. 'already exists')

    def delete_tap(self, idx):
        # type: (int) -> None
        self.call_vpp('tap_delete_v2',
                      sw_if_index=idx)

    def get_taps(self):
        # type: () -> Iterator[dict]
        t = self.call_vpp('sw_interface_tap_dump')
        for iface in t:
            yield {'dev_name': fix_string(iface.dev_name),
                   'sw_if_idx': iface.sw_if_index}

    def is_tap(self, iface_idx):
        # type: (int) -> bool
        for tap in self.get_taps():
            if tap['sw_if_index'] == iface_idx:
                return True
        return False

    #############################

    def create_vhostuser(self, ifpath, mac, tag,
                         qemu_user=None, qemu_group=None, is_server=False):
        # type: (str, str, str, Optional[str], Optional[str], bool) -> int
        t = self.call_vpp('create_vhost_user_if',
                          is_server=is_server,
                          sock_filename=binary_type(ifpath),
                          renumber=False,
                          custom_dev_instance=0,
                          use_custom_mac=True,
                          mac_address=mac_to_bytes(mac),
                          tag=binary_type(tag))

        if is_server and qemu_user is not None and qemu_group is not None:
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
        # type: (int) -> None
        self.call_vpp('delete_vhost_user_if',
                      sw_if_index=idx)

    def get_vhostusers(self):
        # type: () -> Iterator[Tuple[str, int]]
        t = self.call_vpp('sw_interface_vhost_user_dump')

        for interface in t:
            yield (fix_string(interface.interface_name), interface)

    # def is_vhostuser(self, iface_idx):
    #     # type: (int) -> bool
    #     for vhost in self.get_vhostusers():
    #         if vhost.sw_if_index == iface_idx:
    #             return True
    #     return False

    ########################################

    def __init__(self, log, vpp_cmd_queue_len=None, read_timeout=None):
        # type: (logging.Logger, Optional[int], Optional[int]) -> None
        self.LOG = log
        jsonfiles = []
        for root, dirnames, filenames in os.walk('/usr/share/vpp/api/'):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                jsonfiles.append(os.path.join(root, filename))

        self._vpp = vpp_papi.VPP(jsonfiles)

        # Sometimes a callback fires unexpectedly.  We need to catch them
        # because vpp_papi will traceback otherwise
        self._vpp.register_event_callback(self._queue_cb)

        # TODO(ijw) needs better type
        self.registered_callbacks = {}  # type: dict
        for event in self.CallbackEvents:
            self.registered_callbacks[event] = []

        # NB: a real threading lock
        self.event_q_lock = Lock()  # type: Lock
        self.event_q = []  # type: List[dict]

        args = {}

        if vpp_cmd_queue_len is not None:
            args['rx_qlen'] = vpp_cmd_queue_len
        if read_timeout is not None:
            args['read_timeout'] = read_timeout

        self._vpp.connect("python-VPPInterface",
                          **args)

    def call_vpp(self, func, *args, **kwargs):
        # Disabling to prevent message debug flooding
        # self.LOG.debug('VPP: %s(%s, %s): ',
        # func, ', '.join(args), str(kwargs))

        # VPP version 18.04 onwards, the VPP APIs are attributes of the "api"
        # object within the VPPInterface object whereas before 18.04, VPP APIs
        # are attributes of the VPPInterface object itself. The following
        # ensures that we work with VPP version 18.04 and onwards while still
        # being backwards compatible.
        try:
            func_call = getattr(self._vpp.api, func)
        except AttributeError as e:
            func_call = getattr(self._vpp, func)
            # There should not be a need for the debug logs but just in case
            # there is just uncomment them below:
            # self.LOG.debug("Switching to old way of invoking VPP APIs")
            # self.LOG.debug(e)

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

    def disconnect(self):
        # type: () -> None
        self.call_vpp('disconnect')

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

        This is called directly by VPP, and thus appears to be in
        another Python thread (not eventlet) context.

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

    ########################################

    def create_bridge_domain(self, id, mac_age):
        # type: (int, int) -> None
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
        # type: (int) -> None
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

    def get_bridge_domains(self):
        # type: () -> Set[int]
        t = self.call_vpp('bridge_domain_dump', bd_id=0xffffffff)
        return set([bd.bd_id for bd in t])

    def bridge_set_flags(self, bridge_domain_id, flags):
        # type: (int, int) -> None
        """Reset and set flags for a bridge domain.

        TODO(ijw): NOT ATOMIC
        """
        if self.ver_ge(18, 10):
            self.call_vpp('bridge_flags',
                          bd_id=bridge_domain_id,
                          is_set=0,
                          flags=(self.L2_LEARN | self.L2_FWD |
                                 self.L2_FLOOD |
                                 self.L2_UU_FLOOD | self.L2_ARP_TERM))
            self.call_vpp('bridge_flags',
                          bd_id=bridge_domain_id,
                          is_set=1, flags=flags)
        else:
            self.call_vpp('bridge_flags',
                          bd_id=bridge_domain_id,
                          is_set=0,
                          feature_bitmap=(self.L2_LEARN | self.L2_FWD |
                                          self.L2_FLOOD |
                                          self.L2_UU_FLOOD |
                                          self.L2_ARP_TERM))
            self.call_vpp('bridge_flags',
                          bd_id=bridge_domain_id,
                          is_set=1, feature_bitmap=flags)

    def bridge_enable_flooding(self, bridge_domain_id):
        # type: (int) -> None
        self.LOG.debug("Enable flooding (disable mac learning) for bridge %d",
                       bridge_domain_id)
        self.bridge_set_flags(bridge_domain_id, self.L2_UU_FLOOD)

    def get_ifaces_in_bridge_domains(self):
        # type: () -> Dict[int, List[int]]
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

        bridges = collections.defaultdict(list)  # type: Dict[int, List[int]]
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
        # type: (int) -> List[int]
        return self.get_ifaces_in_bridge_domains().get(bd_id, [])

    # These constants are based on those coded into VPP and need to
    # correspond to its values
    # Port not in bridge
    L2_API_PORT_TYPE_NORMAL = 0
    # Port in bridge
    L2_API_PORT_TYPE_BVI = 1

    ########################################

    def add_to_bridge(self, bridx, *ifidxes):
        # type: (int, *int) -> None
        if self.ver_ge(18, 10):
            for ifidx in ifidxes:
                self.call_vpp(
                    'sw_interface_set_l2_bridge',
                    rx_sw_if_index=ifidx, bd_id=bridx,
                    port_type=self.L2_API_PORT_TYPE_NORMAL,  # 18.10+
                    shg=0,              # shared horizon group
                    enable=True)        # enable bridge mode
        else:
            for ifidx in ifidxes:
                self.call_vpp(
                    'sw_interface_set_l2_bridge',
                    rx_sw_if_index=ifidx, bd_id=bridx,
                    bvi=False,  # 18.07-
                    shg=0,              # shared horizon group
                    enable=True)        # enable bridge mode

    def delete_from_bridge(self, *ifidxes):
        # type: (*int) -> None
        if self.ver_ge(18, 10):
            for ifidx in ifidxes:
                self.call_vpp(
                    'sw_interface_set_l2_bridge',
                    rx_sw_if_index=ifidx,
                    bd_id=0,            # no bridge id is necessary
                    port_type=self.L2_API_PORT_TYPE_NORMAL,  # 18.10+
                    shg=0,              # shared horizon group
                    enable=False)       # disable bridge mode (sets l3 mode)
        else:
            for ifidx in ifidxes:
                self.call_vpp(
                    'sw_interface_set_l2_bridge',
                    rx_sw_if_index=ifidx,
                    bd_id=0,            # no bridge id is necessary
                    bvi=False,  # 18.07-
                    shg=0,              # shared horizon group
                    enable=False)       # disable bridge mode (sets l3 mode)

    def set_loopback_bridge_bvi(self, loopback, bridge_id):
        # type: (int, int) -> None
        # Sets the specified loopback interface to act as  the BVI
        # for the bridge. This interface will act as a gateway and
        # terminate the VLAN.
        if self.ver_ge(18, 10):
            self.call_vpp(
                'sw_interface_set_l2_bridge',
                rx_sw_if_index=loopback,
                bd_id=bridge_id,
                shg=0,
                port_type=self.L2_API_PORT_TYPE_BVI,  # 18.10+
                enable=True)
        else:
            self.call_vpp(
                'sw_interface_set_l2_bridge',
                rx_sw_if_index=loopback,
                bd_id=bridge_id,
                shg=0,
                bvi=True,  # 18.07-
                enable=True)

    def get_bridge_bvi(self, bd_id):
        # type: (int) -> Optional[int]
        # Returns a BVI interface index for the specified bridge id
        br_details = self.call_vpp('bridge_domain_dump', bd_id=bd_id)
        if (br_details[0].bvi_sw_if_index and
                int(br_details[0].bvi_sw_if_index) != NO_BVI_SET):
            return br_details[0].bvi_sw_if_index

        return None

    ########################################

    def create_vlan_subif(self, if_id, vlan_tag):
        # type: (int, int) -> int
        t = self.call_vpp('create_vlan_subif',
                          sw_if_index=if_id,
                          vlan_id=vlan_tag)

        # pop vlan tag from subinterface
        self.set_vlan_remove(t.sw_if_index)

        return t.sw_if_index

    def get_vlan_subif(self, if_name, seg_id):
        # type: (str, int) -> Optional[int]
        # We know how VPP makes names up so we can do this
        return self.get_ifidx_by_name('%s.%s' % (if_name, seg_id))

    def delete_vlan_subif(self, sw_if_index):
        # type: (int) -> None
        self.call_vpp('delete_subif',
                      sw_if_index=sw_if_index)

    ########################################

    def acl_add_replace(self, acl_index, tag, rules):
        # type: (int, str, List[dict]) -> int
        t = self.call_vpp('acl_add_replace',
                          acl_index=acl_index,
                          tag=binary_type(tag),
                          r=rules,
                          count=len(rules))
        return t.acl_index

    def set_acl_list_on_interface(self, sw_if_index, input_acls, output_acls):
        # type: (int, List[int], List[int]) -> None
        self.call_vpp('acl_interface_set_acl_list',
                      sw_if_index=sw_if_index,
                      count=len(input_acls) + len(output_acls),
                      n_input=len(input_acls),
                      acls=input_acls + output_acls)

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

    def acl_delete(self, acl_index):
        self.call_vpp('acl_del',
                      acl_index=acl_index)

    def get_acl_tags(self):
        t = self.call_vpp('acl_dump', acl_index=0xffffffff)
        for acl in t:
            if hasattr(acl, 'acl_index'):
                yield (acl.acl_index, fix_string(acl.tag))

    ########################################

    def macip_acl_add(self, rules, count):
        t = self.call_vpp('macip_acl_add',
                          count=count,
                          r=rules)
        return t.acl_index

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

    ########################################

    def ifup(self, *ifidxes):
        """Bring a list of interfaces up

        NB: NOT ATOMIC if multiple interfaces
        """
        for ifidx in ifidxes:
            self.call_vpp('sw_interface_set_flags',
                          sw_if_index=ifidx,
                          admin_up_down=1)

    def ifdown(self, *ifidxes):
        """Bring a list of interfaces down

        NB: NOT ATOMIC if multiple interfaces
        """
        for ifidx in ifidxes:
            self.call_vpp('sw_interface_set_flags',
                          sw_if_index=ifidx,
                          admin_up_down=0)

    ########################################

    def create_loopback(self, mac_address=None):
        # Create a loopback interface to act as a BVI
        if mac_address:
            mac_address = mac_to_bytes(mac_address)
            loop = self.call_vpp('create_loopback', mac_address=mac_address)
        else:
            # We'll let VPP decide the mac-address
            loop = self.call_vpp('create_loopback')
        self.ifdown(loop.sw_if_index)

        return loop.sw_if_index

    def delete_loopback(self, loopback):
        # Delete a loopback interface, this also removes it automatically
        # from the bridge that it was set as the BVI for.
        self.call_vpp('delete_loopback', sw_if_index=loopback)

    ########################################

    def set_interface_vrf(self, if_idx, vrf_id, is_ipv6=False):
        # Set the interface's VRF to the routers's table id
        # allocated by neutron. If the VRF table does not exist, create it.
        self.call_vpp('ip_table_add_del', table_id=vrf_id, is_ipv6=is_ipv6,
                      is_add=True)
        self.call_vpp('sw_interface_set_table', sw_if_index=if_idx,
                      vrf_id=vrf_id, is_ipv6=is_ipv6)

    def get_interface_vrf(self, if_idx):
        # Get the interface VRF
        return self.call_vpp('sw_interface_get_table',
                             sw_if_index=if_idx).vrf_id

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

    def set_interface_address(self, sw_if_index, is_ipv6,
                              address_length, address):
        # TODO(ijw): duplicate; should be removed
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
        # TODO(ijw): duplicate; should be removed
        """Remove an IPv4 or IPv6 address on a software interface."""
        self.call_vpp('sw_interface_add_del_address',
                      sw_if_index=sw_if_index,
                      is_add=0,
                      is_ipv6=is_ipv6,
                      del_all=False,
                      address_length=address_length,
                      address=address)

    def add_ip_route(self, vrf, ip_address, prefixlen, next_hop_address,
                     next_hop_sw_if_index, is_ipv6=False, is_local=False):
        """Adds an IP route in the VRF or exports it from another VRF.

        Checks to see if a matching route is already present in the VRF.
        If not, the route is added or exported.
        The params, ip_address and next_hop_address are integer
        representations of the IPv4 or IPv6 address. To export a
        route from another VRF, the next_hop_addesss is set to None and the
        next_hop_sw_if_index of the interface in the target VRF is provided.
        If is_local is True, a local route is added in the specified VRF.
        """
        if not self.route_in_vrf(vrf, ip_address, prefixlen,
                                 next_hop_address, next_hop_sw_if_index,
                                 is_ipv6, is_local):
            ip = ipaddress.ip_address(six.text_type(bytes_to_ip(ip_address,
                                                    is_ipv6)))
            if next_hop_address is not None:
                next_hop = ipaddress.ip_address(six.text_type(bytes_to_ip(
                    next_hop_address, is_ipv6)))

            if is_local:
                self.LOG.debug('Adding a local route %s/%s in router vrf:%s',
                               ip, prefixlen, vrf)
                self.call_vpp('ip_add_del_route', is_add=1, table_id=vrf,
                              dst_address=ip_address,
                              dst_address_length=prefixlen,
                              is_local=is_local,
                              is_ipv6=is_ipv6,
                              next_hop_via_label=0xfffff + 1)
            elif next_hop_address is not None:
                self.LOG.debug('Adding route %s/%s to %s in router vrf:%s',
                               ip, prefixlen, next_hop, vrf)
                self.call_vpp('ip_add_del_route', is_add=1, table_id=vrf,
                              dst_address=ip_address,
                              dst_address_length=prefixlen,
                              is_local=is_local,
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
                              is_local=is_local,
                              next_hop_sw_if_index=next_hop_sw_if_index,
                              is_ipv6=is_ipv6,
                              next_hop_via_label=0xfffff + 1)

    def delete_ip_route(self, vrf, ip_address, prefixlen, next_hop_address,
                        next_hop_sw_if_index, is_ipv6=False, is_local=False):
        """Deleted an IP route in the VRF.

        Checks to see if a matching route is present in the VRF.
        If present, the route is deleted.
        The params, ip_address and next_hop_address are integer
        representations of the IPv4 or IPv6 address.
        """
        if self.route_in_vrf(vrf, ip_address, prefixlen,
                             next_hop_address, next_hop_sw_if_index,
                             is_ipv6, is_local):
            ip = ipaddress.ip_address(six.text_type(bytes_to_ip(ip_address,
                                                    is_ipv6)))
            if next_hop_address is not None:
                next_hop = ipaddress.ip_address(six.text_type(bytes_to_ip(
                    next_hop_address, is_ipv6)))

            if is_local:
                self.LOG.debug('Deleting a local route %s/%s in router vrf:%s',
                               ip, prefixlen, vrf)
                self.call_vpp('ip_add_del_route', is_add=0, table_id=vrf,
                              dst_address=ip_address,
                              dst_address_length=prefixlen,
                              is_local=is_local,
                              is_ipv6=is_ipv6)
            elif next_hop_address is not None:
                next_hop = ipaddress.ip_address(six.text_type(bytes_to_ip(
                    next_hop_address, is_ipv6)))
                self.LOG.debug('Deleting route %s/%s to %s in router vrf:%s',
                               ip, prefixlen, next_hop, vrf)
                self.call_vpp('ip_add_del_route', is_add=0, table_id=vrf,
                              dst_address=ip_address,
                              dst_address_length=prefixlen,
                              is_local=is_local,
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
                              is_local=is_local,
                              next_hop_sw_if_index=next_hop_sw_if_index,
                              is_ipv6=is_ipv6,
                              next_hop_via_label=0xfffff + 1)

    def route_in_vrf(self, vrf, ip_address, prefixlen,
                     next_hop_address, sw_if_index, is_ipv6=False,
                     is_local=False):
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
        ip = ipaddress.ip_address(six.text_type(bytes_to_ip(ip_address,
                                                is_ipv6)))
        if next_hop_address is not None:
            next_hop = ipaddress.ip_address(six.text_type(
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
                    six.text_type(bytes_to_ip(route.address,
                                  is_ipv6))) == ip and
                # check if the next_hop is present the list
                # of next hops in the route's path
                next_hop in [ipaddress.ip_address(
                    six.text_type(bytes_to_ip(p.next_hop,
                                  is_ipv6))) for p in route.path]):
                self.LOG.debug('Route: %s/%s to %s exists in VRF:%s',
                               ip, prefixlen, next_hop, vrf)
                return True
            elif (sw_if_index and route.table_id == vrf and
                  route.address_length == prefixlen and
                  # check if route.address == ip
                  ipaddress.ip_address(
                      six.text_type(bytes_to_ip(route.address,
                                    is_ipv6))) == ip and
                  # check if the next_hop matches
                  sw_if_index in [p.sw_if_index for p in route.path]):

                self.LOG.debug('Route: %s/%s to sw_if_idx:%s is imported '
                               'into VRF:%s', ip, prefixlen, sw_if_index,
                               vrf)
                return True
            elif (is_local and route.table_id == vrf and
                  route.address_length == prefixlen and
                  ipaddress.ip_address(
                      six.text_type(bytes_to_ip(route.address,
                                                is_ipv6))) == ip and
                  any((p.is_local for p in route.path))):
                self.LOG.debug('Local route: %s/%s exists in VRF:%s',
                               ip, prefixlen, vrf)
                return True
            # Note: The else clause in 'for' loop is executed when the
            # loop terminates without finding a matching route
        else:
            self.LOG.debug('Route: %s/%s to %s does not exist in VRF:%s',
                           ip, prefixlen, next_hop, vrf)
            return False

    def get_local_ip_address(self, ext_intf_ip, is_ipv6=False, vrf=0):
        """A generator of local IP addresses in VPP in a VRF.

        This generates local IPv4 or IPv6 addresses on the same subnet as the
        ext_intf_ip argument in the specified VRF.

        :Param: ext_intf_ip: The external interface address specified in
                             the CIDR (IP/Prefixlen) notation.
        """
        ext_intf_ip = ipaddress.ip_interface(six.text_type(ext_intf_ip))
        if not is_ipv6:
            routes = self.call_vpp('ip_fib_dump')
        else:
            routes = self.call_vpp('ip6_fib_dump')
        for route in routes:
            if (route.table_id == vrf and
                    any((p.is_local for p in route.path))):
                if ipaddress.ip_address(route.address) in ext_intf_ip.network:
                    yield bytes_to_ip(route.address, is_ipv6)

    def get_interface_ip_addresses(self, sw_if_idx):
        """Returns a list of all IP addresses assigned to an interface.

        This will return both v4 and v6 adressess in a list of tuples
        that contains the ip address and subnet mask. e.g.
        [(ipaddress(10.0.0.1), 24), (ipaddress(2001:db8:1234::1), 64)]
        using types from the ipaddress module.
        """
        int_addrs = []
        v4_addrs = self.call_vpp('ip_address_dump', sw_if_index=sw_if_idx,
                                 is_ipv6=False)
        for v4_addr in v4_addrs:
            # Only count the first 4 bytes for v4 addresses
            sanitized_v4 = v4_addr.ip[:4]
            # The standard library has ipinterface, but it's hard
            # to construct with a numeric netmask
            int_addrs.append((ipaddress.ip_address(sanitized_v4),
                             v4_addr.prefix_length))

        v6_addrs = self.call_vpp('ip_address_dump', sw_if_index=sw_if_idx,
                                 is_ipv6=True)
        for v6_addr in v6_addrs:
            int_addrs.append((ipaddress.ip_address(v6_addr.ip),
                             v6_addr.prefix_length))
        return int_addrs

    ########################################

    def set_interface_mtu(self, sw_if_idx, mtu):
        # In VPP 18.07, the mtu field is an array which allows for setting
        # MTU for L3, IPv4, IPv6 and MPLS:
        #
        #     u32 mtu[4]; /* 0 - L3, 1 - IP4, 2 - IP6, 3 - MPLS */
        #
        # Details in the following link:
        #     https://docs.fd.io/vpp/18.07/md_src_vnet_MTU.html
        #
        # TODO(onong): This is a quick fix for 18.07. Further changes may be
        # required after the discussion around jumbo frames
        self.call_vpp('sw_interface_set_mtu', sw_if_index=sw_if_idx,
                      mtu=[mtu, 0, 0, 0])

    ########################################

    # Enables or Disables the NAT feature on an interface
    def set_snat_on_interface(self, sw_if_index, is_inside=1, is_add=1):
        self.call_vpp('nat44_interface_add_del_feature',
                      sw_if_index=sw_if_index,
                      is_inside=is_inside,
                      is_add=is_add)

    # Enable or Disable the dynamic NAT feature on the outside interface
    def snat_overload_on_interface_address(self, sw_if_index, is_add=1):
        """Sets/Removes 1:N NAT overload on the outside interface address."""
        self.call_vpp('nat44_add_del_interface_addr',
                      is_add=is_add,
                      sw_if_index=sw_if_index)

    def get_outside_snat_interface_indices(self):
        """Returns the sw_if_indices of ext. interfaces with SNAT enabled"""
        return [intf.sw_if_index
                for intf in self.call_vpp('nat44_interface_dump')
                if intf.is_inside == 0]

    def get_snat_interfaces(self):
        """Returns the sw_if_indices of all interfaces with SNAT enabled"""
        snat_interface_list = []
        snat_interfaces = self.call_vpp('nat44_interface_dump')
        for intf in snat_interfaces:
            snat_interface_list.append(intf.sw_if_index)
        return snat_interface_list

    def get_snat_local_ipaddresses(self):
        # NB: Only IPv4 SNAT addresses are supported.
        snat_local_ipaddresses = []
        snat_static_mappings = self.call_vpp('nat44_static_mapping_dump')
        for static_mapping in snat_static_mappings:
            snat_local_ipaddresses.append(
                str(ipaddress.IPv4Address(
                    static_mapping.local_ip_address[:4])))
        return snat_local_ipaddresses

    def clear_snat_sessions(self, ip_addr):
        """Clear any dynamic NAT translations if present for the ip_addr."""
        user_vrf = None
        snat_users = self.call_vpp('nat44_user_dump')
        for user in snat_users:
            if ipaddress.IPv4Address(ip_addr) == ipaddress.IPv4Address(
                    user.ip_address):
                user_vrf = user.vrf_id
                break
        # A NAT session exists if the user_vrf is set
        if user_vrf is not None:
            packed_ip_addr = str(ipaddress.IPv4Address(ip_addr).packed)
            user_sessions = self.call_vpp('nat44_user_session_dump',
                                          ip_address=packed_ip_addr,
                                          vrf_id=user_vrf
                                          )
            for session in user_sessions:
                # Delete all dynamic NAT translations
                if not session.is_static:
                    self.call_vpp('nat44_del_session',
                                  is_in=1,   # inside
                                  protocol=session.protocol,
                                  address=packed_ip_addr,
                                  vrf_id=user_vrf,
                                  port=session.inside_port)

    def get_snat_static_mappings(self):
        return self.call_vpp('nat44_static_mapping_dump')

    def set_snat_static_mapping(self, local_ip, external_ip, tenant_vrf,
                                is_add=1):
        local_ip = str(ipaddress.IPv4Address(local_ip).packed)
        external_ip = str(ipaddress.IPv4Address(external_ip).packed)
        self.call_vpp('nat44_add_del_static_mapping',
                      local_ip_address=local_ip,
                      external_ip_address=external_ip,
                      external_sw_if_index=0xFFFFFFFF,  # -1 = Not used
                      local_port=0,     # 0 = ignore
                      external_port=0,  # 0 = ignore
                      addr_only=1,      # 1 = address only mapping
                      vrf_id=tenant_vrf,
                      is_add=is_add)    # 1 = add, 0 = delete

    def get_snat_addresses(self):
        ret_addrs = []
        addresses = self.call_vpp('nat44_address_dump')
        for addr in addresses:
            ret_addrs.append(str(ipaddress.ip_address(addr[3][:4]).exploded))

        return ret_addrs

    ########################################

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

    def add_lisp_ndp_entry(self, mac, bridge_domain, ipv6_address):
        """Adds a static IPv6 NDP entry to LISP.

        ipv6_address is the packed representation of a IPv6 address.
        """
        self.call_vpp('one_add_del_ndp_entry',
                      is_add=1,
                      mac=mac_to_bytes(mac),
                      bd=bridge_domain,
                      ip6=ipv6_address
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

    def del_lisp_ndp_entry(self, mac, bridge_domain, ipv6_address):
        """Removes a static IPv6 NDP entry from LISP.

        ipv6_address is the packed representation of a v6 address.
        """
        self.call_vpp('one_add_del_ndp_entry',
                      is_add=0,
                      mac=mac_to_bytes(mac),
                      bd=bridge_domain,
                      ip6=ipv6_address
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

    def replace_lisp_ndp_entry(self, mac, bridge_domain, ipv6_address):
        """Replaces the LISP NDP entry in a bridge domain for the v6 address.

        ipv6_adddress is a packed representation of the IPv6 address.
        """
        # Delete the current NDP entry for the ipv6_address in the BD
        for mac_addr, ip6 in [(ndp_entry.mac, ndp_entry.ip6) for ndp_entry in
                              self.call_vpp('one_ndp_entries_get',
                                            bd=bridge_domain).entries
                              if ndp_entry.ip6 == ipv6_address]:
            self.call_vpp('one_add_del_ndp_entry',
                          is_add=0, mac=mac_addr, bd=bridge_domain, ip6=ip6)
        # Add the new v6 NDP entry
        self.add_lisp_ndp_entry(mac, bridge_domain, ipv6_address)

    def exists_lisp_arp_entry(self, bridge_domain, ipv4_address):
        """Return True if a LISP ARP entry exists in the bridge_domain.

        ipv4_address is an integer representation of the IPv4 address.
        """
        return ipv4_address in [arp.ip4 for arp in
                                self.call_vpp('one_l2_arp_entries_get',
                                              bd=bridge_domain).entries]

    def exists_lisp_ndp_entry(self, bridge_domain, ipv6_address):
        """Return True if a LISP NDP entry exists in the bridge_domain.

        ipv6_address is the packed representation of the IPv6 address.
        """
        return ipv6_address in [ndp_entry.ip6 for ndp_entry in
                                self.call_vpp('one_ndp_entries_get',
                                              bd=bridge_domain).entries]

    def clear_lisp_arp_entries(self, bridge_domain):
        """Clear LISP ARP entries in the bridge_domain."""
        for mac, ip4 in [(arp.mac, arp.ip4) for arp in
                         self.call_vpp('one_l2_arp_entries_get',
                                       bd=bridge_domain).entries]:
            self.call_vpp('one_add_del_l2_arp_entry',
                          is_add=0, mac=mac, bd=bridge_domain, ip4=ip4)

    def clear_lisp_ndp_entries(self, bridge_domain):
        """Clear LISP NDP entries in the bridge_domain."""
        for mac, ip6 in [(ndp_entry.mac, ndp_entry.ip6) for ndp_entry in
                         self.call_vpp('one_ndp_entries_get',
                                       bd=bridge_domain).entries]:
            self.call_vpp('one_add_del_ndp_entry',
                          is_add=0, mac=mac, bd=bridge_domain, ip6=ip6)

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

    ########################################

    def cross_connect(self, source_idx, dest_idx):
        self.LOG.debug("Enable cross connected between %d-->%d",
                       source_idx, dest_idx)
        self.call_vpp('l2_patch_add_del',
                      rx_sw_if_index=source_idx,
                      tx_sw_if_index=dest_idx,
                      is_add=1)

    ########################################

    #  direction : 1 = rx, 2 = tx, 3 tx & rx
    def enable_port_mirroring(self, src_idx, dst_idx, direction=3, is_l2=1):
        self.LOG.debug("Enable span from %d to %d",
                       src_idx, dst_idx)
        self.call_vpp('sw_interface_span_enable_disable',
                      sw_if_index_from=src_idx,
                      sw_if_index_to=dst_idx,
                      state=direction,
                      is_l2=is_l2)

    def disable_port_mirroring(self, source_idx, dest_idx):
        self.LOG.debug("Disable span from %d to %d",
                       source_idx, dest_idx)
        self.call_vpp('sw_interface_span_enable_disable',
                      sw_if_index_from=source_idx,
                      sw_if_index_to=dest_idx,
                      state=0)

    def dump_port_mirroring(self):
        self.LOG.debug("Dump span")
        t = self.call_vpp('sw_interface_span_dump')
        return t

    L2_LEARN = (1 << 0)
    L2_FWD = (1 << 1)
    L2_FLOOD = (1 << 2)
    L2_UU_FLOOD = (1 << 3)
    L2_ARP_TERM = (1 << 4)

    ########################################

    def create_vxlan_tunnel(self, src_addr, dst_addr, is_ipv6, vni):
        self.LOG.debug("Create vxlan tunnel VNI: %d", vni)
        # Device instance (ifidx) is selected for us (~0)
        # Decap graph node left to its default (~0)
        t = self.call_vpp('vxlan_add_del_tunnel',
                          is_add=1,
                          is_ipv6=is_ipv6,
                          instance=0xffffffff,
                          src_address=src_addr,
                          dst_address=dst_addr,
                          decap_next_index=0xffffffff,
                          vni=vni)
        return t.sw_if_index

    def delete_vxlan_tunnel(self, src_addr, dst_addr, is_ipv6, vni):
        self.LOG.debug("Delete vxlan tunnel VNI: %d", vni)
        self.call_vpp('vxlan_add_del_tunnel',
                      is_add=0,
                      is_ipv6=is_ipv6,
                      src_address=src_addr,
                      dst_address=dst_addr,
                      vni=vni)

    def get_vxlan_tunnels(self):
        """Get the list of existing vxlan tunnels in this node

        Tunnels returned as a hash: (vni, dest) => tunnel ifidx
        """
        t = self.call_vpp('vxlan_tunnel_dump', sw_if_index=0xffffffff)
        tuns = {}
        for tun in t:
            tuns[(tun.vni, tun.dst_address,)] = tun.sw_if_index
        return tuns
