# Copyright (c) 2018 Cisco Systems, Inc.
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


# Constants and variables reflecting paths in etcd for data.

leadin = '/networking-vpp'

state_key_space = LEADIN + '/state'
node_key_space = LEADIN + '/nodes'
secgroup_key_space = LEADIN + '/global/secgroups'
remote_group_key_space = LEADIN + '/global/remote_group'
gpe_key_space = LEADIN + '/global/networks/gpe'
election_key_space = LEADIN + '/election'

routers_dir = 'routers/'
router_fip_dir = 'routers/floatingip/'

def _path(*args):
    return '/'.join(args)

def secgroup_key(group):
    return _path(secgroup_key_space, group)

def remote_secgroup_key(secgroup_id):
    """Path to a directory of ports in a security group

    Used for 'remote-security-group' implementation, hence the name.
    """

def remote_secgroup_port_key(secgroup_id, port_id):
    """Path to a directory of ports in a security group

    Used for 'remote-security-group' implementation, hence the name.
    """
    return _path(remote_secgroup_key(secgroup_id), port_id)

def port_key(host, port):
    return _path(port_key_space, host, "ports", port['id'])

def gpe_segment_key(segmentation):
    """The path to a dir containing IP address records for a MAC on a segment"""
    return _path(etcd_paths.gpe_key_space, segmentation)

def gpe_if_key(segmentation, host, mac):
    """The path to a dir containing IP address records for a MAC on a segment"""
    return _path(gpe_segment_key(segmentation, host, mac)

def gpe_locator_key(if_path, ip):
    """The path to a dir containing IP address records for a MAC on a segment"""
    return _path(if_path, str(ip))

