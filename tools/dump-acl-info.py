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

    t = conn.sw_interface_dump()

    for iface in t:
        mac = bytearray(iface.l2_address[:iface.l2_address_length])
        yield {'name': fix_string(iface.interface_name),
               'tag': fix_string(iface.tag),
               'mac': ':'.join(["%02x" % int(c) for c in mac]),
               'sw_if_index': iface.sw_if_index,
               'sup_sw_if_index': iface.sup_sw_if_index}


def get_acls(self):
    # get all ACLs
    global conn

    t = conn.acl_dump(acl_index=0xffffffff)
    for acl in t:
        if hasattr(acl, 'acl_index'):
            yield {
                'acl_idx': acl.acl_index,
                'acl_tag': fix_string(acl.tag)
            }


def get_if_macip_acls(sw_if_index):
    global conn

    def get_acl_rules(t):
        for f in t.r:
            yield decode_macip_acl_rule(f)

    # This gets all MACIP ACLs, index by interface
    if_acls = conn.macip_acl_interface_get()
    # Ours is indexed...
    # This is a spot of weirdness in the API
    f = if_acls.acls[sw_if_index]

    if f == 0xffffffff:
        return  # no ACL, no rules

    t = conn.macip_acl_dump(acl_index=f)
    t = t[0]

    yield {
        'acl_index': t.acl_index,
        'tag': fix_string(t.tag),
        'rules': get_acl_rules(t)
    }


def get_if_acls(sw_if_index):
    global conn

    t = conn.acl_interface_list_dump(
        sw_if_index=sw_if_index
    )
    # We're dumping one interface
    t = t[0]

    def get_acl_rules(l):
        for f in l:
            yield decode_acl_rule(f)

    count = 0
    for det in t.acls:
        is_input = (count < t.n_input)

        dump = conn.acl_dump(acl_index=det)
        dump = dump[0]  # one acl
        yield {
            'is_input': is_input,
            'acl_index': det,
            'tag': dump.tag,
            'rules': get_acl_rules(dump.r)  # an iterator
        }
        count = count + 1


protos = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    41: 'IPv6',
    46: 'RSVP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'IPv6-ICMP',
    59: 'IPv6-NoNxt',
    60: 'IPv6-Opts',
    88: 'EIGRP',
    89: 'OSPF',
    103: 'PIM',
    112: 'VRRP',
    115: 'L2TP',
}


def decode_proto(num):
    global protos

    return protos.get(num, 'proto-%s' % str(num))


for intf in get_interfaces():
    print('Interface %d, name %s tag "%s"'
          % (intf['sw_if_index'], intf['name'], intf['tag']))
    for macip in get_if_macip_acls(intf['sw_if_index']):
        print('    MACIP %d tag "%s"' % (macip['acl_index'], macip['tag']))
        for rule in macip['rules']:
            print('        %s %s: %s mask %s %s/%d' % (
                ('permit' if rule['is_permit']
                 else 'not permit (%s)' % str(rule['is_permit'])),
                'ipv6' if rule["is_ipv6"] else 'ipv4',
                format_mac(rule["src_mac"]),
                format_mac(rule['src_mac_mask']),
                str(rule["src_ip_addr"]),
                rule['src_ip_prefix_len']))
    for acl in get_if_acls(intf['sw_if_index']):
        print('    ACL %d (%s)' % (acl['acl_index'],
                                   'input' if acl['is_input']
                                   else 'output'))
        for rule in acl['rules']:
            print('        %s %s: %s %s/%d[%d-%d] -> %s/%d[%d-%d] '
                  'TCP(%d mask %d)' % (
                      ('permit' if rule['is_permit']
                       else 'not permit (%s)' % str(rule['is_permit'])),
                      'ipv6' if rule["is_ipv6"] else 'ipv4',
                      decode_proto(rule["proto"]),
                      str(rule["src_ip_addr"]), rule['src_ip_prefix_len'],
                      rule['src_range'][0],
                      rule['src_range'][1],
                      str(rule["dst_ip_addr"]), rule['dst_ip_prefix_len'],
                      rule['dst_range'][0],
                      rule['dst_range'][1],
                      rule["tcp_flags_mask"],
                      rule["tcp_flags_value"]))
