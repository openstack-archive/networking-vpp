# Copyright (c) 2016 Cisco Systems, Inc.
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

from networking_vpp import etcdutils
from networking_vpp import jwt_agent

from oslo_config import cfg
from oslo_serialization import jsonutils


class SignedEtcdJSONWriter(etcdutils.EtcdJSONWriter):
    """Write Python datastructures to etcd with a signature.

    This includes both the data and a signature confirming
    its source and authenticity.
    """

    def __init__(self, etcd_client):
        self.jwt_agent = jwt_agent.JWTUtils(
            cfg.CONF.ml2_vpp.jwt_node_cert,
            cfg.CONF.ml2_vpp.jwt_node_private_key,
            cfg.CONF.ml2_vpp.jwt_ca_cert,
            cfg.CONF.ml2_vpp.jwt_controller_name_pattern)
        super(SignedEtcdJSONWriter, self).__init__(etcd_client)

    def _process_read_value(self, key, value):
        value = jsonutils.loads(value)
        if (self.jwt_agent.should_path_be_signed(key)):
            signerNodeName = self.jwt_agent.get_signer_name(key)
            value = self.jwt_agent.verify(signerNodeName,
                                          key,
                                          value)
        return value

    def _process_written_value(self, key, value):
        if (self.jwt_agent.should_path_be_signed(key)):
            value = self.jwt_agent.sign(key, value)
        return jsonutils.dumps(value)