#!/usr/bin/python
import vpp_papi
import time


conn = vpp_papi.VPP()
conn.connect('stats-client')


def fix_string(s):
    return s.rstrip("\0").decode(encoding='ascii')



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


from collections import defaultdict

global ifs
global simple_counters
global combined_counters
ifs={}
simple_counters = defaultdict(dict)
combined_counters = defaultdict(dict)

# This comes from vpp's interface.h and isn't properly exposed in the Python API yet

global vnet_simple_counters
global vnet_combined_counters

vnet_simple_counters=[
    'drop',
    'punt',
    'ip4',
    'ip6',
    'rx_no_buf',
    'rx_miss',
    'rx_error',
    'tx_error',
    'mpls'
]

vnet_combined_counters=[
    'rx',
    'tx'
]

def save(t, iface, counter, val):
    if t == 'vnet_interface_simple_counters':
        simple_counters[ifs[iface]][vnet_simple_counters[counter]] = val
    else:
        combined_counters[ifs[iface]][vnet_combined_counters[counter]] = val

def cb(t, val):
    if t in ('vnet_interface_simple_counters',
             'vnet_interface_combined_counters'):
        for f in range(0, val.count):
            save(t, val.first_sw_if_index + f, val.vnet_counter_type, val.data[f])
    else:
        print 'Unknown callback type %s' % t

def main():

    conn.want_stats(enable_disable=True)

    conn.register_event_callback(cb)

    global ifs
    for intf in get_interfaces():
        ifs[intf['sw_if_index']] = intf['name']

    time.sleep(10)

    for f in sorted(set(simple_counters.keys()) | set(combined_counters.keys())):
        print 'Interface %s:' % f
        stats = simple_counters.get(f, {})
        for g in sorted(stats.keys()):
            print '%s: %d' % (g, stats[g])
        stats = combined_counters.get(f, {})
        for g in sorted(stats.keys()):
            print '%s: %d packets, %d bytes' % (g, stats[g].packets, stats[g].bytes)

if __name__ == '__main__':
    main()
