#!/usr/bin/python

# Copyright (c) 2017 Cisco Systems, Inc.
# All Rights Reserved.
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

import binascii
from ipaddress import ip_address
import vpp_papi


conn = vpp_papi.VPP()

conn.connect('debug-acl-client')


def vpp_call(func, *args, **kwargs):
    global conn
    if hasattr(conn, 'api'):
        return getattr(conn.api, func)(*args, **kwargs)
    return getattr(conn, func)(*args, **kwargs)


def fix_string(s):
    return s.rstrip("\0").decode(encoding='ascii')


def decode_acl_rule(t):
    return {
        "is_permit": t.is_permit,
        "is_ipv6": t.is_ipv6,
        "src_ip_addr": decode_addr(t.src_ip_addr, t.is_ipv6),
        'src_ip_prefix_len': t.src_ip_prefix_len,
        "dst_ip_addr": decode_addr(t.dst_ip_addr, t.is_ipv6),
        'dst_ip_prefix_len': t.dst_ip_prefix_len,
        "proto": t.proto,
        'src_range': [t.srcport_or_icmptype_first, t.srcport_or_icmptype_last],
        'dst_range': [t.dstport_or_icmpcode_first, t.dstport_or_icmpcode_last],
        "tcp_flags_mask": t.tcp_flags_mask,
        "tcp_flags_value": t.tcp_flags_value
    }


def decode_macip_acl_rule(t):
    return {
        "is_permit": t.is_permit,
        "is_ipv6": t.is_ipv6,
        "src_mac": t.src_mac,
        'src_mac_mask': t.src_mac_mask,
        "src_ip_addr": decode_addr(t.src_ip_addr, t.is_ipv6),
        'src_ip_prefix_len': t.src_ip_prefix_len
    }


def pairs(lst):
    i = iter(lst)

    while i:
        yield i.next(), i.next()


def decode_addr(addr, is_ipv6):
    if is_ipv6:
        return ip_address(addr[0:16])
    else:
        return ip_address(addr[0:4])


def mac_address(iface):
    return bytearray(iface.l2_address[:iface.l2_address_length])


def _pack_mac(mac_address):
    """Pack a mac_address into binary."""
    return binascii.unhexlify(mac_address.replace(':', ''))


def format_mac(mac):
    return ':'.join(['%02x' % ord(x) for x in mac])


def get_interfaces():

    global conn

    t = vpp_call('sw_interface_dump')

    for iface in t:
        mac = bytearray(iface.l2_address[:iface.l2_address_length])
        yield {'name': fix_string(iface.interface_name),
               'tag': fix_string(iface.tag),
               'mac': ':'.join(["%02x" % int(c) for c in mac]),
               'sw_if_index': iface.sw_if_index,
               'sup_sw_if_index': iface.sup_sw_if_index}


def main():
    for intf in get_interfaces():
        print('%5d %30s %64s' % (intf['sw_if_index'],
                                 intf['name'],
                                 intf['tag']))

if __name__ == '__main__':
    main()
