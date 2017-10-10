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

import etcd
import jsonutils
import logging
import re
import sys

from networking_vpp.agent import vpp
from networking_vpp.compat import n_const

LOG = logging.Logger('test-vpp-content')
# TODO(ijw): this isn't keeping logs quiet
LOG.setLevel(logging.ERROR)

VPP_CMD_QUEUE_LEN = 32
vpp = vpp.VPPInterface(LOG, None)

etcd_client = etcd.Client(port=2379)

# This tests one host.  Give it the host you're running on as an argument
binding_host = sys.argv[1]

######################################################################
# TODO(ijw): pull out to a common file


def VPP_TAG(tag):
    return 'net-vpp.' + tag

# MAX_PHYSNET_LENGTH + the tag format must be <= the 64 bytes of a VPP tag
MAX_PHYSNET_LENGTH = 32
TAG_PHYSNET_IF_PREFIX = VPP_TAG('physnet:')
TAG_UPLINK_PREFIX = VPP_TAG('uplink:')
TAG_L2IFACE_PREFIX = VPP_TAG('port:')

# Interface tagging naming scheme :
# tap and vhost interfaces: port:<uuid>
# Uplink Connectivity: uplink:<net_type>.<seg_id>


def decode_physnet_if_tag(tag):
    if tag is None:
        return None
    m = re.match('^' + TAG_PHYSNET_IF_PREFIX + '([^.]+)$', tag)
    return None if m is None else m.group(1)


def decode_uplink_tag(tag):
    """Spot an uplink interface tag.

    Return (net_type, seg_id) or None if not an uplink tag
    """
    if tag is None:
        return None  # not tagged
    m = re.match('^' + TAG_UPLINK_PREFIX + '([^.]+)\.([^.]+)\.([^.]+)$', tag)
    return None if m is None else (m.group(1), m.group(2), m.group(3))


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

def main():
    # Find everything in etcd that we might expect to see
    vpp_ports = {}
    uplink_ports = {}
    physnet_ports = {}
    unknown_ports = []
    for f in vpp.get_interfaces():
        # Find downlink ports
        port_id = decode_port_tag(f['tag'])
        if port_id is not None:
            vpp_ports[port_id] = f
        else:
            uplink_tag = decode_uplink_tag(f['tag'])
            if uplink_tag is not None:
                uplink_ports[uplink_tag] = f
            else:
                physnet = decode_physnet_if_tag(f['tag'])
                if physnet is not None:
                    physnet_ports[physnet] = f
                else:
                    unknown_ports.append(f)

    for f in unknown_ports:
        print('INFO: Unknown port: %s (%d)' % (f['name'], f['sw_if_idx']))

    # Physnets want checking against the ML2 config
    for physnet, f in physnet_ports.items():
        print('INFO: Physnet %s is on port %s (%d)' %
              (physnet, f['name'], f['sw_if_idx']))

    # Confirm only the ports we expect to find are in etcd
    port_dir_in_etcd = '/networking-vpp/nodes/%s/ports' \
        % (binding_host)
    port_keypatt = re.compile(r'^/networking-vpp/nodes/([^/]+)/ports/([^/]+)$')
    result = etcd_client.read(port_dir_in_etcd, recursive=True)

    etcd_ports = {}
    for val in result.children:
        k = val.key
        res = port_keypatt.match(k)
        if res:
            host = res.group(1)
            if host != binding_host:
                continue
            uuid = res.group(2)
            print('INFO: port %s found in etcd' % uuid)
            etcd_ports[uuid] = jsonutils.loads(val.value)

    # Try and find the intersection, which should correspond, and the
    # differences, which shouldn't exist

    etcd_portset = frozenset(etcd_ports.keys())
    vpp_portset = frozenset(vpp_ports.keys())

    unexpected_ports = vpp_portset - etcd_portset
    unbound_ports = etcd_portset - vpp_portset
    ports_to_check = vpp_portset & etcd_portset

    if unexpected_ports:
        print('ERROR: unexpectedly bound ports in VPP: %s' %
              ', '.join(unexpected_ports))

    if unbound_ports:
        print('ERROR: unbound ports in etcd: %s' %
              ', '.join(unbound_ports))

    for f in ports_to_check:
        # etcd_value = etcd_ports[f]
        # vpp_port = vpp_ports[f]

        # Is this port bound to the VM correctly?
        pass

    # "binding_type": "tap"

    # "mtu": 1500
    # "mac_address": "fa:16:3e:2e:1d:8d"
    # "port_security_enabled": false

    # "security_groups": []}

    # "allowed_address_pairs": []
    # "fixed_ips": [{"subnet_id": "da52a3aa-a899-46c9-992e-b2b4294ce9ce"
    # "ip_address": "10.0.0.2"}
    # {"subnet_id": "51d259ab-8b6f-4a77-8375-8b364a497ab8"
    # "ip_address": "fd20:1bce:4726:0:f816:3eff:fe2e:1d8d"}]

    # Is this port in the correct network?

    etcd_networks = set()
    for name, val in etcd_ports.items():
        # Take note of the network for future checks - networks in etcd
        # are implied by their ports.
        etcd_networks.add((val["physnet"], val["network_type"],
                           val["segmentation_id"],))

    # Are the VPP uplinks we know about linked correctly to their physnets?

    # Are there any VPP bridges other than those that are linked to uplinks?

    # Are ports in the right bridges for their networking requirements?

    # Are the ACLs in VPP tagged?

    # Are the tagged ACLs populated correctly?

    # Do ports have the right ACLs bound?

if __name__ == '__main__':
    main()
