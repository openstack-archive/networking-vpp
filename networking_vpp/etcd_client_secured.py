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

from collections import namedtuple
import etcd


from networking_vpp import config_opts

from networking_vpp import etcd_path_helper
from networking_vpp import jwt_utils

from oslo_config import cfg
from oslo_log import log as logging

import re

LOG = logging.getLogger(__name__)

cfg.CONF.register_opts(config_opts.vpp_opts, "ml2_vpp")


class EtcdClientSecured(etcd.client.Client):
    """This class provides authentication to the etcd objects.

    Only the objects whose path matches regular expression
    jwt_controller_path_pattern or jwt_computeNode_path_pattern are
    authenticated.
    A JWT token is added when the objects are written.
    When the objects are read, the authenticity is verified. If the
    verification fails, a SecurityError is raised.
    In etcd_client, all the functions that write or read the data are
    implemented by calling internally self.write or self.read. So whatever
    the public method (set, get, test_and_set, watch, update ...) called in
    etcd_client, the corresponding overloaded method (read or write) in
    etcd_client_secured will be called.
    Current limitations:
    About the write operations, EtcdClientSecured doesn't support
    prevValue for the signed keys. The append mode is not supported neither.
    """

    def _get_signer_name(self, key):
        nodeName = namedtuple('nodeName', 'isRegexp value')
        controllerNodeName = cfg.CONF.ml2_vpp.jwt_controller_name

        m = re.match(etcd_path_helper.etcd_computeNode_path_pattern,
                     key)
        if m:
            computeNodeName = m.group(m.lastindex)
            nn = nodeName(False, computeNodeName)
            return(nn)

        m = re.match(etcd_path_helper.etcd_controller_path_pattern,
                     key)
        if m:
            nn = nodeName(True, controllerNodeName)
            return(nn)

        nn = nodeName(False, "")
        return(nn)

    def _check_etcdRes(self, rv):
        for f in rv.children:
            signerNodeName = self._get_signer_name(f.key)
            f.value = self.jwt_agent.verify_jwt(signerNodeName,
                                                f.key,
                                                f.value)

    def __init__(self, *args, **kwargs):
        self.jwt_agent = jwt_utils.JWTUtils()
        super(EtcdClientSecured,
              self).__init__(*args, **kwargs)

    def write(self, key, value, ttl=None, dir=False,
              append=False, **kwdargs):
        value = self.jwt_agent.get_jwt(key, value)
        ret = super(EtcdClientSecured, self).write(key, value, ttl,
                                                   dir, append,
                                                   **kwdargs)
        return(ret)

    def read(self, key, **kwdargs):
        ret = super(EtcdClientSecured, self).read(key, **kwdargs)
        self._check_etcdRes(ret)
        return(ret)
