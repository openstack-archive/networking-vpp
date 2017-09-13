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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import oid
import datetime
import jwt
from OpenSSL import crypto
import re

from networking_vpp._i18n import _


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


class JWTSigningFailed(Exception):
    """Indicates a key verification failed"""
    pass


class JWTUtils(object):
    """Create and to verify JWT tokens in a key space hierarchy."""

    def _verify_certificate(self, vcert):
        """Confirm this certificate is in a chain of trust

        We have a CA, and we want to know we're seeing a certificate
        that this CA has signed.
        """
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM,
                                              vcert)

        store_ctx = crypto.X509StoreContext(self.store, certificate)
        result = store_ctx.verify_certificate()
        if result is not None:
            raise JWTSigningFailed(_("Certificate is not trusted"))

    def _make_jwt_payload(self, path, value, delta=0):
        """Convert data into the form we will sign

        :param path: the path to which this will be stored
        :param value: the value to store
        :param delta: how old this can be and still be valid (0 = forever)

        Use 'delta' with caution: in state stores, keys can hang around
        forever if the state doesn't change.
        """

        jwt_payload = {
            "version": 1,
            "value": value,
            "path": path}

        if delta > 0:
            jwt_payload["expires"] = datetime.datetime.utcnow() + \
                datetime.timedelta(seconds=delta)
        return(jwt_payload)

    def _check_node_name(self, nodeName, vcert_obj):
        """Check the common name of the signer certificate.

        Verify the role of the signer certificate matches the expected
        role of the signer.
        :param nodeName: A named tuple containing either the expected signer
        hostname or a regexp to check the signer hostname.
        :param vcert_obj: The X509 certificate of the signer
        raise: JWTSigningError if not valid.
        """

        subject_name = vcert_obj.subject
        commonNames = subject_name.get_attributes_for_oid(
            oid.NameOID.COMMON_NAME)

        commonName = commonNames[0]
        if nodeName.isRegexp:
            if re.match(nodeName.value, commonName.value):
                return
        elif nodeName.value == commonName.value:
            return

        raise JWTSigningFailed(
            _("cert says node name is %(cn)s and we want %(nn)s") %
            {'cn': commonName.value, 'nn': str(nodeName.value)})

    def _check_path(self, dval, path):
        """Check the signed path matches where the data was found

        :param dval: the signed data
        :param path: the path at which the signed data was stored
        :raise JWTSigningError: if not valid.
        """
        if (dval["path"] != path):
            raise JWTSigningFailed(
                _("path is %(dpth)s in data and we want %(pth)s")
                % {'dpth': dval["path"], 'pth': path})

    def _get_crypto_material(self, filename):
        """Load a file with key material.

        :param filename: the location of the key material
        :raise IOError: if there are problems reading it.
        """
        with open(filename, "rb") as c_file:
            return c_file.read()

    def __init__(self, local_cert, priv_key, ca_cert, controller_name_re):
        """Initialize JWTUtils

        Load the local node certificate, the node private
        key and the CA certificate from files; prepare for both
        signing and validation of key-value pairs.

        Signing will take place with the local certificate, and the
        public half will be added to signed objects.

        Validation will take place with the CA certificate, along with
        other checks that the signing matches the payload.

        :param local_cert: file containing public half of the local key
        :param priv_key: file containing private half of the local key
        :param ca_cert: file containing CA root certificate
        raise: IOError if the files cannot be read.
        """

        priv_key_pem = self._get_crypto_material(priv_key)
        self.private_key = serialization.load_pem_private_key(
            priv_key_pem,
            password=None,
            backend=default_backend())

        self.node_certificate = self._get_crypto_material(local_cert)
        self.node_cert_obj = load_pem_x509_certificate(
            self.node_certificate,
            default_backend())
        self.node_cert_pem = self.node_cert_obj.public_bytes(
            serialization.Encoding.PEM)

        ca_certificate = self._get_crypto_material(ca_cert)

        # pyopenssl
        root_ca = crypto.load_certificate(crypto.FILETYPE_PEM,
                                          ca_certificate)
        self.store = crypto.X509Store()
        self.store.add_cert(root_ca)

        self.controller_name_re = controller_name_re

    def get_signer_name(self, key):
        """Return the expected hostname of key signer.

        If key path contains the signer hostname (it matches the
        computeNode_path_pattern), returns the hostname found in the path.
        If key path matches controller_path_pattern, return the
        controller_name_pattern regexp.
        If key path matches neither computeNode_path_pattern nor
        controller_path_pattern, the key is not signed; returns an empty
        signer name.
        :param key: the pathname of the key.
        :return : a namedtuple containing either the hostname of the
            signer or a regular expression to check the signer hostname.
        """
        nodeName = namedtuple('nodeName', 'isRegexp value')
        controllerNodeNameRegExp = self.controller_name_re

        m = re.match(etcd_computeNode_path_pattern,
                     key)
        if m:
            computeNodeName = m.group(m.lastindex)
            nn = nodeName(False, computeNodeName)
            return(nn)

        m = re.match(etcd_controller_path_pattern,
                     key)
        if m:
            nn = nodeName(True, controllerNodeNameRegExp)
            return(nn)

        nn = nodeName(False, "")
        return(nn)

    def should_path_be_signed(self, path):
        if (re.match(etcd_controller_path_pattern, path)
                or re.match(etcd_computeNode_path_pattern, path)):
            return(True)
        else:
            return(False)

    def sign(self, path, value, delta=0):
        """Sign value with local key.

        Create a JWT token to authenticate the value and return a
        payload with that token embedded.
        :param path: the path where the value will be stored.
        :param value: The object to be authenticated
        :param delta: How long this payload is valid (0 = forever)
        :return: a dictionary containing the the JWT token including
                 the value, and the certificate.
        """

        # TODO(ijw): we want a signature rather than an encrypted payload
        # or this will make debugging hard (or perhaps the option for
        # both).  JWT seems to embody a 'claim' rather than data, so
        # perhaps we should claim 'the hash of this object, serialised
        # consistently, is XXX'.  To make a hash I find recommended
        # hashlib.md5(json.dumps(data, sort_keys=True).encode('utf-8')).
        # hexdigest()
        # - better hashing algos may exist so that may want changing,
        # but the json and the encode part should mean that you get
        # an ASCII representation of the value and it's consistent
        # (specifically the key order of dicts are not arbitrary).
        jwt_payload = self._make_jwt_payload(path, value, delta)

        jwtok = jwt.encode(jwt_payload,
                           self.private_key,
                           algorithm='RS256')

        sgn_value = {
            "jwt": jwtok,
            "certificate": self.node_cert_pem}

        return sgn_value

    def verify(self, signer_requirements, path, sgn_value):
        """Verify the authenticity of the incoming data

        :param signer_requirements: what we expect of the key; right now,
        the CN of the signer
        :param path: path where the JSON object was found
        :param sgn_value: The datastructure found at that path
        :return: confirmed original value from JWT token.
        :raise A JWTSigningFailed is raised if the verification fails.
        """

        if sgn_value is None:
            raise JWTSigningFailed(
                _("Invalid empty value at path %s") % (path))

        try:
            # Load the certificate and verify that it is both a suitable
            # certificate for this key and one we trust the origin of
            vcert_str = sgn_value.get("certificate", "")
            # ("" is an invalid key)

            # TODO(ijw): why?
            vcert_str = vcert_str.encode('ascii', 'ignore')
            # TODO(ijw): how does this fail?
            vcert_obj = load_pem_x509_certificate(
                vcert_str,
                default_backend())

            vpublic_key = vcert_obj.public_key()

            self._check_node_name(signer_requirements, vcert_obj)
            # TODO(ijw): what checks the cert is signed with the CA?
            self._verify_certificate(vcert_str)

            # Unpack the JWT to its raw data
            jwtok = sgn_value.get("jwt", "")
            # ("" is an invalid token)
            dval = jwt.decode(jwtok, vpublic_key, algorithm='RS256')

            # Check the ancillary tags of the raw data
            self._check_path(dval, path)
            # TODO(ijw): check delta

            # Get and return the originally provided value
            return dval["value"]

        except jwt.InvalidTokenError:
            raise JWTSigningFailed(_("InvalidTokenError: path :%s") % path)
