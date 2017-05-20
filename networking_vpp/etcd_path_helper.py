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


"""
These regular expressions are used to identify the etcd paths that need
to be signed. A value in etcd will be signed if and only if its path matches
one of the following regexp.
If the path matches etcd_controller_path_pattern, it has to be signed by a
controller (i.e. mech_vpp). In this case, the common name of the signer
certificate has to match to the regexp  given in the configuration parameter
jwt_controller_name_pattern.
If the path matches etcd_computeNode_path_pattern, it has to be signed by a
computeNode (i.e. agent/server ). In this case, the common name of the signer
certificate has to be equal to the computeNode hostname as found in the path
via the regexp.
"""
etcd_controller_path_pattern =\
    "^/networking-vpp/nodes/.*$|" +\
    "^/networking-vpp/global/secgroups/.*$"
etcd_computeNode_path_pattern =\
    "^/networking-vpp/state/([^/]+)/.*$|" +\
    "^/networking-vpp/global/networks/gpe/[^/]+/([^/]+)/.*$"
