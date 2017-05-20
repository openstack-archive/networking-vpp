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
import mock

from networking_vpp import jwt_agent
from neutron.tests import base
from oslo_serialization import jsonutils


node_cert = "-----BEGIN CERTIFICATE-----\n\
MIIDUTCCAjmgAwIBAgIRAPsiF3EkqGBqrrywIRicwXwwDQYJKoZIhvcNAQELBQAw\n\
GjEYMBYGA1UEAwwPb3BlbnN0YWNrLmxvY2FsMB4XDTE3MDMwNjA4MjM1N1oXDTI3\n\
MDMwNDA4MjM1N1owEDEOMAwGA1UEAwwFZXRjZDIwggEiMA0GCSqGSIb3DQEBAQUA\n\
A4IBDwAwggEKAoIBAQDODKLwFOB9UlWPx6BqvtdJiEDS3LGgBbpVCPbFfP0xjcGd\n\
spJln0WuTwOt+JAzNQ5vSa1l42vkv2GbQfKhPLzEVX6bgfJ5bspT2AFxOLESTJyx\n\
dgzqV8EeWVGSBhmm5i2iT8lKldb+0hJAW2Xc3ZRHSUcGAy69AsemeQhj/ovQHEfb\n\
Vpeqsgm0FdWXptBy1a2fK05dq2juYW+69tJuO7FWKK9Tn1GmEAL927KvmIXOaUnQ\n\
uTCUEtB+SwX//huJhKwbou2MhvDQ2CD9ERGkA008CgiySvQ5r8somUakzZALqBqY\n\
L44UdxnPWIVJrKRqSh5AwbCT50rdcBJtzefChxHZAgMBAAGjgZswgZgwCQYDVR0T\n\
BAIwADAdBgNVHQ4EFgQUMw41nL+BF62OHx2fkS9xZj4jK/owSgYDVR0jBEMwQYAU\n\
dF/u4iWXkwkQOvxLzCBn324zpPuhHqQcMBoxGDAWBgNVBAMMD29wZW5zdGFjay5s\n\
b2NhbIIJAOolbdKIMiGCMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIF\n\
oDANBgkqhkiG9w0BAQsFAAOCAQEAdUE7IBPO5QR0yNlQaHND28MB9fa36LZQEBKt\n\
Dfwh8UsmqNefH3FHq3Qv5s2b0ySvJ3ZLNu6mHkcBIk9+YEZ8TFE5RxG0VomTcV6k\n\
KvMNvvz/m8u3lqUyFlYSwSMwc5g1I1hjKhIIL6m8GpAq+3iwM4JshBfc5n9HA5qd\n\
RsZOyfpcZ2BGYX6gRuPr9XlLlUS4mMlfvflslTnZNeJKBUdAa9BUIOKtZsgfnpy0\n\
Sq1SHrYvuNKrNOl1wusG/59uuX333jdOUPIuEJfcZ3AQjF9sJYFgpXlcX/ac+3ex\n\
bGpL9V/LhazYKH9tI8GtiBTy6ADoo5tyQ6JLUqoONBH2IUt8IQ==\n\
-----END CERTIFICATE-----"

node_key = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDODKLwFOB9UlWP\n\
x6BqvtdJiEDS3LGgBbpVCPbFfP0xjcGdspJln0WuTwOt+JAzNQ5vSa1l42vkv2Gb\n\
QfKhPLzEVX6bgfJ5bspT2AFxOLESTJyxdgzqV8EeWVGSBhmm5i2iT8lKldb+0hJA\n\
W2Xc3ZRHSUcGAy69AsemeQhj/ovQHEfbVpeqsgm0FdWXptBy1a2fK05dq2juYW+6\n\
9tJuO7FWKK9Tn1GmEAL927KvmIXOaUnQuTCUEtB+SwX//huJhKwbou2MhvDQ2CD9\n\
ERGkA008CgiySvQ5r8somUakzZALqBqYL44UdxnPWIVJrKRqSh5AwbCT50rdcBJt\n\
zefChxHZAgMBAAECggEAax6oqrW/y4c9UiVPIY+bbu/1+2mesnmn2ENzv1Huc4+l\n\
w60tbMVzvV34pL4fgW+o1HRyQBEOa3qPbN7JG8fuvwdPbdsNytGtQA+BGHKHo+LO\n\
Z3fe2QnMLVH0FT00os7xlHt0Q2FIx2tA79JUT5GmX7UZxmdrKfpC/ynXEd0opITQ\n\
itw7hFQRVgpjqSjheGzBmEjIhdMKA+nvX+KdqxAhM3W8SMBsFhAg9F8CQfKO1JOU\n\
jzDmf7+WRfoYSu5PIyRCsiH+X3aMERfV4ImoUj9RKfl/VUg2GpSQnhDeimOzyBdF\n\
v83B0vru3LzAxtL+WutoMwPnahkSLfuddTPhGJN9fQKBgQDnj9GfKceElxsp9oFL\n\
mVLAWr1Ud1dIkGNkWT5Z/V6wZdfbm+QW7iHaoKbb8MwcnRw7T4Ly69H6Bo/KyuAZ\n\
zSVl7Cr0YnQ2sErL51s5ubka2kQ5GYohCcdZIZw8E0Y6oYKq9hndlj/2WhdaaMfp\n\
lzwJczdV/4aNp9MELpxSETt3cwKBgQDjy4o2Y8+hgbmoDH+gUzWgIZIS01/yXGoz\n\
yrenoxBhaRWRdy7llZk3BQSkIC19Z0qg8unfq7V89cOGPzBHlmb/3nsHD7FtiuEl\n\
7Qbq41ekra+19DqLWZqnhS9selMPNT3hIJjSWhGWC3Ts9/ZbCkhbVqpC6U8xRgKO\n\
IbrX2PLGgwKBgCi4pO9thHWvsQo3HFO0GdZT3rms5v+OzLvH6ewfX3h74HLxPjI+\n\
HFv7JnzFIs/hXSac+/VGPT3Py5epB7Hh3rLGzmL9sVwwsmabP/Kt03yCZ77229Cl\n\
jJYDEBuMdCw5XOY9sxzBoGvtOfAfPxC4FMnApjmMXxgoLDavD7Rq7V87AoGABJhU\n\
f2hgBdgCELu/z1IeYM6MjcipxM/MbKMINV96sxxVjQukbIkqAAwf3dewUzlELh74\n\
TMS/8ndarFiV9ru39C1eufO9FoKYrBUt8IsJd47xXnBAxhLWpc5v+HY3OrVOPD5W\n\
FtguRqKQhz8xPwDkGMOUx6jBKjNJVeikRjpgG1UCgYAQCZzeu7vY/7ndyM/9K7QK\n\
pOex+7twj6596/LnE0o27ZX0CB0b0CvJcYYDLEuidE+sTi5e5/eV/R8n+nVYQwqX\n\
2Lw48JoFGFp8Ux6vA4NIi2LdMT5jli0Q/DPT1+Lg3/zwSxRvNAWfuFY+R0lKofk0\n\
5naxaIzK+EP6lOe5U2ldPA==\n\
-----END PRIVATE KEY-----"

ca_cert = "-----BEGIN CERTIFICATE-----\n\
MIIDQTCCAimgAwIBAgIJAOolbdKIMiGCMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNV\n\
BAMMD29wZW5zdGFjay5sb2NhbDAeFw0xNzAzMDYwNTQyMjVaFw0yNzAzMDQwNTQy\n\
MjVaMBoxGDAWBgNVBAMMD29wZW5zdGFjay5sb2NhbDCCASIwDQYJKoZIhvcNAQEB\n\
BQADggEPADCCAQoCggEBAKcIzk7LK4iA7J5uy6QUvmgK+FhbEK/h5jI1FYuWLYDp\n\
L5L/CylmQsxhcOp0JYeMM0znuVPhf3mhoGKQsFaPgKVS3Vmx8mvAlq76AmaDZ/7W\n\
J9u6yFICJDXktn00Gd3bbBuBj0JuaF/QOMulXlRY/4xO88zv3N5Po0uRgYG5Yz8s\n\
DdNUaifXvdwKXkIXM1HMVXeBYqv/yp0YRUW+zTduoxPgxT5MkJ5JlYwuxjdmTk2k\n\
y2lCHXCICZsSO70AP7cR5XjaEDlUsA4TF+nsoe2wjUDDiri5JzNvPE9M77JwbQo1\n\
1p+qtjzugfsQ0pjkvwkW3n/+/pe/53c9ipjz+umiKtsCAwEAAaOBiTCBhjAdBgNV\n\
HQ4EFgQUdF/u4iWXkwkQOvxLzCBn324zpPswSgYDVR0jBEMwQYAUdF/u4iWXkwkQ\n\
OvxLzCBn324zpPuhHqQcMBoxGDAWBgNVBAMMD29wZW5zdGFjay5sb2NhbIIJAOol\n\
bdKIMiGCMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUA\n\
A4IBAQCW4PLX6jnOLTmY+6qXx8EL6vkXGzH9LO9X1Z0xSnkFgx7RfFYwZ60KuglO\n\
bGP7+Mn5/7bQCXf/TBpZx+Qh4dl/b4wbAuaYRb4AYLw8mTkOumwQl1Pd+Ki7skx3\n\
MawAGIbG+11nLHcbUcG9GaYZnH6vp6ycbU8T39FcYijSQbL2yEAfiutdljTrEiiU\n\
RGm49ummHO37ggiZdXtwtUFfqHHJBM5AyNRe9/X/UmVbqZ/QpWVI9w5sUvXJZpiP\n\
+0PI+ewIIgW2hjxN22oKqO/6B9UOThBeou0nBrniFmigUFEcOYk4Feh8TmAGgM/G\n\
oLLwSxoCoUSnJdASkEE/SLRPcnLC\n\
-----END CERTIFICATE-----"


class JWTUtilsTestCase(base.BaseTestCase):

    def fake_crypto(self, name):
        if (name == "jwt_private_key.pem"):
            return (node_key)
        if (name == "jwt_node_cert.pem"):
            return (node_cert)
        if (name == "jwt_ca_cert.pem"):
            return (ca_cert)
        else:
            return(None)

    def corrupt_jwt(self, sgn):
        jwt = sgn['jwt']
        sjwt = jwt.split('.')

        sjwt[1] = chr(ord(sjwt[1][0]) + 1) + sjwt[1][1:]

        jwt = ".".join(sjwt)
        sgn['jwt'] = jwt
        return sgn

    @mock.patch.object(jwt_agent.JWTUtils, '_get_crypto_material')
    def setUp(self, mck):
        super(JWTUtilsTestCase, self).setUp()

        mck.side_effect = self.fake_crypto

        self.jwt_agent = jwt_agent.JWTUtils(
            "jwt_node_cert.pem", "jwt_private_key.pem", "jwt_ca_cert.pem",
            "Controller.*")

    def test_signature(self):
        key = '/networking-vpp/test'
        value = {"segmentation_id": "1312", "mtu": "1500"}
        value = jsonutils.dumps(value)
        sgn = self.jwt_agent.sign(key, value)
        nodeName = namedtuple('nodeName', 'isRegexp value')
        signer_requirements = nodeName(True, 'etcd.*')
        rval = self.jwt_agent.verify(signer_requirements, key, sgn)
        self.assertEqual(rval, value)

    def test_bad_signature(self):
        key = '/networking-vpp/test'
        value = {"segmentation_id": "1312", "mtu": "1500"}
        value = jsonutils.dumps(value)
        sgn = self.jwt_agent.sign(key, value)
        sgn = self.corrupt_jwt(sgn)
        nodeName = namedtuple('nodeName', 'isRegexp value')
        signer_requirements = nodeName(True, 'etcd.*')
        self.assertRaises(jwt_agent.JWTSigningFailed,
                          self.jwt_agent.verify, signer_requirements, key, sgn)
