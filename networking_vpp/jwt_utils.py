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


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import oid

import datetime

import jwt

from OpenSSL import crypto

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from networking_vpp import config_opts
from networking_vpp import etcd_path_helper

import re

LOG = logging.getLogger(__name__)

cfg.CONF.register_opts(config_opts.vpp_opts, "ml2_vpp")


class SecurityError(Exception):
    pass


class JWTUtils(object):

    def _verify_certificate(self, vcert):
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM,
                                              vcert)

        store_ctx = crypto.X509StoreContext(self.store, certificate)
        result = store_ctx.verify_certificate()
        if result is None:
            return True
        else:
            LOG.error(
                ("Verify JWT verify certificate failed ") %
                (vcert))
            return False

    def _is_path_signed(self, path):
        if (re.match(self.etcd_controller_path_pattern, path)
                or re.match(self.etcd_computeNode_path_pattern, path)):
            return(True)
        else:
            return(False)

    def _get_tmp_value(self, path, value, delta=0):
        tmp_value = dict(value)
        tmp_value["_path"] = path

        tmp_value.pop("_jwt", None)
        tmp_value.pop("_certificate", None)
        if delta > 0:
            tmp_value["_exp"] = datetime.datetime.utcnow() + \
                datetime.timedelta(seconds=delta)
        else:
            tmp_value.pop("_exp", None)
        return(tmp_value)

    def _check_node_name(self, nodeName, vcert_obj):
        subject_name = vcert_obj.subject
        commonNames = subject_name.get_attributes_for_oid(
            oid.NameOID.COMMON_NAME)

        commonName = commonNames[0]
        LOG.debug(
            ("Verify JWT checkNodeName :%s; %s") % (nodeName,
                                                    commonName.value))
        if (nodeName != commonName.value):
            LOG.error(
                ("Verify JWT checkNodeName failed :%s; %s") %
                (nodeName, commonName.value))
            return(False)
        else:
            return(True)

    def _check_path(self, dval, pathName):
        if (dval["_path"] == pathName):
            return(True)
        else:
            LOG.error(("Verify JWT check path failed :%s; %s") %
                      (pathName, dval["_path"]))
            return(False)

    def _check_dval(self, dval, value):
        for k in value.keys():
            if (k == "_jwt") or (k == "_certificate"):
                continue

            if (value[k] != dval[k]):
                LOG.error(
                    ("Verify JWT check dval failed :%s; %s") %
                    (value[k], dval[k]))
                return(False)

        if ("_exp" in dval.keys()):
            delta = 0
        else:
            delta = 1
        if (len(value.keys()) != len(dval.keys()) + delta):
            LOG.error("dval, val length mismatched : %d,%d" %
                      (len(value.keys()), len(dval.keys())))
            return(False)

        return(True)

    def __init__(self):
        self.jwt_signing = False
        if (cfg.CONF.ml2_vpp.jwt_signing):
            self.jwt_signing = True

            self.etcd_controller_path_pattern = \
                etcd_path_helper.etcd_controller_path_pattern

            self.etcd_computeNode_path_pattern = \
                etcd_path_helper.etcd_computeNode_path_pattern

            with open(cfg.CONF.ml2_vpp.jwt_node_private_key,
                      "rb") as key_file:
                self.private_key = \
                    serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend())

            with open(cfg.CONF.ml2_vpp.jwt_node_cert,
                      "rb") as cert_file:
                self.node_certificate = cert_file.read()

            with open(cfg.CONF.ml2_vpp.jwt_ca_cert,
                      "rb") as cert_file:
                self.ca_certificate = cert_file.read()

            self.node_cert_obj = load_pem_x509_certificate(
                self.node_certificate,
                default_backend())

            self.node_cert_pem = self.node_cert_obj.public_bytes(
                serialization.Encoding.PEM)

            # pyopenssl
            root_ca = crypto.load_certificate(crypto.FILETYPE_PEM,
                                              self.ca_certificate)
            self.store = crypto.X509Store()
            self.store.add_cert(root_ca)

    def add_jwt(self, path, value):
        """If the path needs to be signed, add a JWT token to the JSON value

        :param path: the path where the value will be stored.
        :param value: The JSON object to be authenticated
        :return : if the signature is needed, a JSON object with the JWT token.
        """
        LOG.debug(("Add JWT :%s") % (path))
        if not self.jwt_signing:
            return(value)

        if (self._is_path_signed(path)):
            LOG.debug(("Add JWT Signing1 :%s;%s") % (path, value))
            value = jsonutils.loads(value)
            tmp_val = self._get_tmp_value(
                path,
                value,
                cfg.CONF.ml2_vpp.jwt_max_duration)

            jwtok = jwt.encode(tmp_val,
                               self.private_key,
                               algorithm='RS256')
            value["_jwt"] = jwtok
            value["_certificate"] = self.node_cert_pem
            value = jsonutils.dumps(value)
            LOG.debug(("Add JWT Signing2 :%s;%s") % (path, value))
        return(value)

    def verify_jwt(self, signerNodeName, path, value):
        """Verify the authenticity of the JSON object

        :param signerNodeName: Name of the signer
        :param path: path where the JSON object is stored
        :param value: The JSON object to verify
        :return: True. A SecurityError is raised if the verification fails.
        """
        LOG.debug(("Verify JWT :%s; %s") % (path, value))
        if not self.jwt_signing:
            return(True)

        if not (self._is_path_signed(path)):
            return(True)
        try:
            LOG.debug(("Verify JWT2 :%s; %s") % (path, value))
            if (value is None):
                return(True)

            if (len(value) == 0):
                return(True)

            value = jsonutils.loads(value)
            LOG.debug(("Verify JWT3 :%s; %s") % (path, value))
            vcert_str = value["_certificate"]
            vcert_str = vcert_str.encode('ascii', 'ignore')
            vcert_obj = load_pem_x509_certificate(
                vcert_str,
                default_backend())

            vpublic_key = vcert_obj.public_key()

            if not (self._check_node_name(signerNodeName,
                                          vcert_obj)):
                raise SecurityError(
                    _("check Node Name failed: path:%s") % (path))

            if not (self._verify_certificate(vcert_str)):
                raise SecurityError(
                    _("verify Certificate failed: path:%s") % (path))

            jwtok = value["_jwt"]
            dval = jwt.decode(jwtok,
                              vpublic_key,
                              algorithm='RS256')

            if not (self._check_dval(dval, value)):
                raise SecurityError(_("check dval failed: path:%s") % (path))

            if not (self._check_path(dval, path)):
                raise SecurityError(_("check path failed: path:%s") % (path))

            return(True)

        except jwt.InvalidTokenError:
            LOG.error(("InvalidTokenError : path :%s") % (path))
            raise SecurityError(_("InvalidTokenError : path :%s") % (path))
