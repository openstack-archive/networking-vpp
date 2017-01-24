# Copyright (c) 2017 ENEA
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

import abc
from abc import abstractmethod
import mech_vpp
from networking_vpp.agent import utils as nwvpp_utils
from networking_vpp.db import db
from neutron import context as n_context
from neutron.db import api as neutron_db_api
import six


@six.add_metaclass(abc.ABCMeta)
class GenericFeature(object):
    """Abstract class to handle etcd notifications.

    Base class for Server side and agent side feature implementation.
    For each 'feature', the pattern is the following:
    - write new data in the configuration space:
      * under 'LEADIN/nodes/<host>/<feature>/<unique_id>' for a specific
        host configuration
      * under 'LEADIN/global/<feature>/<unique_id>' for global configurations

    - for both cases, the agent returns data under the operational space:
      'LEADIN/state/<host>/<feature>/<unique_id>'

    For etcd method, the corresponding key_* method is called.
    """

    """'path': instance property which is used as a key for the return state.

    Whether the feature is global or not, the path must not contain
    any forward slash ('/').
    """
    path = ''

    """ For system wide features, the path is LEADING/global/<path>/<uuid>
    """
    is_global = False

    def key_create(self, host, key, value):
        """Feature for host was created.

        Typically, the wanted behaviour is the same as 'set'.
        """
        self.key_set(host, key, value)

    @abstractmethod
    def key_set(self, host, key, value):
        """Feature for host was set.

        This is called on creation or update for a key.
        """
        pass

    @abstractmethod
    def key_delete(self, host, key, value):
        """Feature for host was deleted.

        In this case, the value will always be 'None'.
        """
        pass

    def key_expire(self, host, key, value):
        """Key has expired.

        Default behaviour: No action
        """
        pass

    def resync(self):
        """Resync with etcd state.

        On resync call, we must typically clean internal cached
        values as the whole tree will be read, and method 'key_set'
        will be called for each key/value pair.
        """
        pass

    # Utility functions
    @abstractmethod
    def _etcd_write(self, uuid, data):
        """Generic API to insert new data to etcd.

        The actual implementation will write either to
        the configuration path:
            - /node/host/feature/uuid
            - /global/feature/uuid
        or to the operational path: /state/host/feature/uuid
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ServerFeature(GenericFeature):
    """Server-side base class for feature implementation."""

    def __init__(self, conf, communicator, session=None, context=None):
        """Constructor.

        params:
        - conf: configuration class cfg.CONF
        - communicator: the agent does not write directly to
                        etcd, but uses a journalism mechanism
        - session: a neutron db_api session
        - context: neutron admin context
        """
        self.conf = conf
        self._communicator = communicator
        self._session = session or neutron_db_api.get_session()
        self._context = context or n_context.get_admin_context()
        pass

    def _configuration_key_space(self, host):
        if self.is_global:
            return (mech_vpp.LEADIN + '/global/%s' % (self.path))
        else:
            return (mech_vpp.LEADIN + '/nodes/%s/%s' % (host, self.path))

    def _build_path(self, host, uuid):
        return (self._configuration_key_space(host) + '/' + str(uuid))

    def _etcd_write(self, host, uuid, data):
        """Server side implementation.

        The actual implementation will write to the configuration path
            - /node/host/feature/uuid
            - /global/feature/uuid
        """
        db.journal_write(self._session,
                         self._build_path(host, uuid),
                         data)
        self._communicator.kick()


@six.add_metaclass(abc.ABCMeta)
class AgentFeature(GenericFeature):
    """Agent-side base class for feature implementation."""

    def __init__(self, conf, etcd_client, vppf):
        """Constructor.

        params:
        - conf: configuration class (typically cfg.CONF)
        - etcd_client: etcd.Client instance
        - vppf: VPPForwarder instance
        """
        self.conf = conf
        self.host = conf.host
        self.etcd_client = etcd_client
        self.etcd_helper = nwvpp_utils.EtcdHelper(self.etcd_client)
        self.vppf = vppf
        pass

    def _operational_key_space(self, host):
        return (mech_vpp.LEADIN + '/state/%s/%s' % (host, self.path))

    def _build_path(self, host, uuid):
        return (self._operational_key_spacee(host) + '/' + str(uuid))

    def _etcd_write(self, host, uuid, data):
        """Agent side implementation.

        The actual implementation will write to the operational path
            - /state/host/feature/uuid
        """
        self.etcd_client.write(self._build_path(host or self.host, uuid), data)

    def tick(self):
        """Method called at each watch timeout."""
        pass
