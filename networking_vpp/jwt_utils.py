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
    """Utility class to create and to verify JWT token in a key space hierarchy.

    """

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

    def _should_path_be_signed(self, path):
        if (re.match(self.etcd_controller_path_pattern, path)
                or re.match(self.etcd_computeNode_path_pattern, path)):
            return(True)
        else:
            return(False)

    def _get_jwt_payload(self, path, value, delta=0):
        jwt_payload = {}
        jwt_payload["_value"] = value
        jwt_payload["_path"] = path

        if delta > 0:
            jwt_payload["_exp"] = datetime.datetime.utcnow() + \
                datetime.timedelta(seconds=delta)
        return(jwt_payload)

    def _check_node_name(self, nodeName, vcert_obj):
        subject_name = vcert_obj.subject
        commonNames = subject_name.get_attributes_for_oid(
            oid.NameOID.COMMON_NAME)

        commonName = commonNames[0]
        if ((nodeName.isRegexp and re.match(nodeName.value, commonName.value))
                or (not nodeName.isRegexp
                    and nodeName.value == commonName.value)):
            return(True)
        else:
            LOG.error(
                ("Verify JWT checkNodeName failed :%s; %s") %
                (nodeName.value, commonName.value))
            return(False)

    def _check_path(self, dval, pathName):
        if (dval["_path"] == pathName):
            return(True)
        else:
            LOG.error(("Verify JWT check path failed :%s; %s") %
                      (pathName, dval["_path"]))
            return(False)

    def _get_crypto_material(slef, filename):
        with open(filename, "rb") as c_file:
            dta = c_file.read()
            return(dta)

    def __init__(self):
        """Initialize JWTUtils according to the configuration.

        If JWT signing is enable, load the node certificate, the node private
        key and the CA certificate.

        raise: IOError if the certificate files or the key file are missing.
        """
        self.jwt_signing = False
        if (cfg.CONF.ml2_vpp.jwt_signing):
            self.jwt_signing = True

            self.etcd_controller_path_pattern = \
                etcd_path_helper.etcd_controller_path_pattern

            self.etcd_computeNode_path_pattern = \
                etcd_path_helper.etcd_computeNode_path_pattern

            self.priv_key_pem = self._get_crypto_material(
                cfg.CONF.ml2_vpp.jwt_node_private_key)
            self.private_key = \
                serialization.load_pem_private_key(
                    self.priv_key_pem,
                    password=None,
                    backend=default_backend())

            self.node_certificate = self._get_crypto_material(
                cfg.CONF.ml2_vpp.jwt_node_cert)

            self.ca_certificate = self._get_crypto_material(
                cfg.CONF.ml2_vpp.jwt_ca_cert)

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

    def get_jwt(self, path, value):
        """Sign value if needed.

        If the path needs to be signed, create a JWT token to authenticate
        the value.
        :param path: the path where the value will be stored.
        :param value: The object to be authenticated
        :return : if a signature is needed, a JSON object with the JWT token
                  and the certificate.
        """

        if (self._should_path_be_signed(path)):
            sgn_value = {}
            jwt_payload = self._get_jwt_payload(
                path,
                value,
                cfg.CONF.ml2_vpp.jwt_max_duration)

            jwtok = jwt.encode(jwt_payload,
                               self.private_key,
                               algorithm='RS256')
            sgn_value["_jwt"] = jwtok
            sgn_value["_certificate"] = self.node_cert_pem
            value = jsonutils.dumps(sgn_value)
        return(value)

    def verify_jwt(self, signerNodeName, path, value):
        """Verify the authenticity of the JSON object

        :param signerNodeName: Name of the signer
        :param path: path where the JSON object is stored
        :param value: The JSON object to verify
        :return: decoded value from JWT token.
        :raise A SecurityError is raised if the verification fails.
        """

        if not (self._should_path_be_signed(path)):
            return(value)
        try:
            if (value is None) or (len(value) == 0):
                raise SecurityError(
                    _("Invalid value: path:%s") % (path))

            value = jsonutils.loads(value)
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

            if not (self._check_path(dval, path)):
                raise SecurityError(_("check path failed: path:%s") % (path))

            value = dval["_value"]
            return(value)

        except jwt.InvalidTokenError:
            LOG.error(("InvalidTokenError : path :%s") % (path))
            raise SecurityError(_("InvalidTokenError : path :%s") % (path))
