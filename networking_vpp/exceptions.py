# Copyright (c) 2016 Cisco Systems, Inc.
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

from networking_vpp._i18n import _
from networking_vpp.compat import n_exc


class InvalidEtcdCAConfig(n_exc.NeutronException):
    message = _("Invalid etcd CA config.")


class InvalidEtcHostsConfig(n_exc.NeutronException):
    message = _("Invalid etc host config. Expect comma-separated list of "
                "<Host> or <Host:Port> format")


class InvalidEtcHostConfig(n_exc.NeutronException):
    message = _("Invalid etc host config. Expect an IP or host name in "
                "the form <Host> or <Host:Port>")


class GpeVNIRangeError(n_exc.NeutronException):
    """An exception indicating an invalid GPE VNI range was specified.

    :param vni_range: The invalid vni range specified in the
                      'start:end' format
    """
    message = _("Invalid VNI range string for the GPE network. Expect a "
                "string in the form %(vni_range)s")

    def __init__(self, **kwargs):
        # Convert the vni_range tuple to 'start:end' format for display
        if isinstance(kwargs['vni_range'], tuple):
            kwargs['vni_range'] = "%d:%d" % kwargs['vni_range']
        super(GpeVNIRangeError, self).__init__(**kwargs)


class GpeVNIInUse(n_exc.NeutronException):
    """GPE network creation failed exception due to the VNI being in use.

    :param vni_id: The ID of the GPE VNI that's in use.
    """
    message = _("Invalid GPE VNI value %(vni_id)s for allocation "
                "The VNI is already in use by another GPE network")


class GpeVNIInvalid(n_exc.NeutronException):
    """GPE network creation failed exception due to the VNI being invalid.

    :param vni_id: The ID of the GPE VNI that's invalid.
    """
    message = _("Invalid GPE VNI value %(vni_id)s for allocation "
                "or deallocation ")


class GpeVNIUnavailable(n_exc.NeutronException):
    """GPE network creation failed exception due to a VNI being unavailable.

    """
    message = _("A GPE VNI is unavailable for allocation")
