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


import etcd_jwt

from networking_vpp import config_opts

from oslo_config import cfg
from oslo_log import log as logging

import re

LOG = logging.getLogger(__name__)

cfg.CONF.register_opts(config_opts.vpp_opts, "ml2_vpp")


class etcd_client_secured(etcd.client.Client):

        def _get_signer_name(self, key):
                controllerNodeName = cfg.CONF.ml2_vpp.JWT_controller_name

                m = re.match(cfg.CONF.ml2_vpp.JWT_computeNode_path_pattern,
                             key)
                if m:
                        computeNodeName = m.group(1)
                        return(computeNodeName)

                m = re.match(cfg.CONF.ml2_vpp.JWT_controller_path_pattern,
                             key)
                if m:
                        return(controllerNodeName)

                return("")

        def _check_etcdRes(self, rv):
                for f in rv.children:
                        LOG.debug("Check EtcdResult: %s;%s" % (f.key, f.value))
                        signerNodeName = self._get_signer_name(f.key)
                        if not (self.jwt_agent.verify_jwt(signerNodeName,
                                                          f.key,
                                                          f.value)):
                                raise etcd.EtcdException("JWT invalid")

        def __init__(
            self,
            host='127.0.0.1',
            port=4001,
            srv_domain=None,
            version_prefix='/v2',
            read_timeout=60,
            allow_redirect=True,
            protocol='http',
            cert=None,
            ca_cert=None,
            username=None,
            password=None,
            allow_reconnect=False,
            use_proxies=False,
            expected_cluster_id=None,
            per_host_pool_size=10,
            lock_prefix="/_locks"):

                self.jwt_agent = etcd_jwt.etcd_jwt()
                super(etcd_client_secured,
                      self).__init__(host, port, srv_domain, version_prefix,
                                     read_timeout, allow_redirect, protocol,
                                     cert, ca_cert, username, password,
                                     allow_reconnect, use_proxies,
                                     expected_cluster_id, per_host_pool_size,
                                     lock_prefix)

        def write(self, key, value, ttl=None, dir=False,
                  append=False, **kwdargs):
                LOG.debug(("etcd_client_secured write0 :%s;%s") % (key, value))
                value = self.jwt_agent.add_jwt(key, value)
                LOG.debug(("etcd_client_secured write1 :%s;%s") % (key, value))
                ret = super(etcd_client_secured, self).write(key, value, ttl,
                                                             dir, append,
                                                             **kwdargs)
                return(ret)

        def read(self, key, **kwdargs):
                LOG.debug(("etcd_client_secured read0 :%s") % (key))
                ret = super(etcd_client_secured, self).read(key, **kwdargs)
                LOG.debug(("etcd_client_secured read1 :%s;%s") % (key, ret))
                self._check_etcdRes(ret)
                return(ret)
