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

import re

from networking_vpp.compat import n_const

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


def physnet_if(physnet_name):
    return TAG_PHYSNET_IF_PREFIX + physnet_name


def decode_physnet_if(tag):
    if tag is None:
        return None
    m = re.match('^' + TAG_PHYSNET_IF_PREFIX + '([^.]+)$', tag)
    return None if m is None else m.group(1)


def uplink(physnet, net_type, seg_id):
    return TAG_UPLINK_PREFIX + '%s.%s.%s' % (physnet, net_type, seg_id)


def decode_uplink(tag):
    """Spot an uplink interface tag.

    Return (net_type, seg_id) or None if not an uplink tag
    """
    if tag is None:
        return None  # not tagged
    m = re.match('^' + TAG_UPLINK_PREFIX + '([^.]+)\.([^.]+)\.([^.]+)$', tag)
    return None if m is None else (m.group(1), m.group(2), m.group(3))


def port(port_uuid):
    return TAG_L2IFACE_PREFIX + str(port_uuid)


def decode_port(tag):
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


def common_spoof(is_vm_ingress):
    if is_vm_ingress:
        return COMMON_SPOOF_VPP_TO_VM_TAG
    else:
        return COMMON_SPOOF_VM_TO_VPP_TAG


def decode_common_spoof(tag):
    """Work out if this tag is one of our common spoof filter tags

    """
    if COMMON_SPOOF_VPP_TO_VM_TAG == tag:
        return 1
    if COMMON_SPOOF_VM_TO_VPP_TAG == tag:
        return 0

    return None

SECGROUP_TAG = VPP_TAG('secgroup:')


def secgroup(secgroup_id, is_vm_ingress):
    base_tag = SECGROUP_TAG + secgroup_id
    return DIRECTION_TAG(base_tag, is_vm_ingress)


def decode_secgroup(tag):
    # Matches the formats constructed earlier
    m = re.match('^' + SECGROUP_TAG + '(' + n_const.UUID_PATTERN + ')\.(.*)$',
                 tag)
    if m:
        secgroup_id = m.group(1)
        dirmark = m.group(2)
        is_vm_ingress = dirmark == VPP_TO_VM_MARK
        return secgroup_id, is_vm_ingress

    return None, None

