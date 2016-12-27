# Copyright (c) 2016 Qosmos
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
import six


@six.add_metaclass(abc.ABCMeta)
class ServerFeature(object):
    """Abstract class to handle etcd notifications.

    For each 'feature', the pattern is the following:
    - write new data in the configuration space:
      * under 'LEADIN/nodes/<host>/<feature>/<unique_id>' for a specific
        host configuration
      * under 'LEADIN/global/<feature>/<unique_id>' for global configurations

    - for both cases, the agent returns data under the operational space:
      'LEADIN/state/<host>/<feature>/<unique_id>'

    For etcd method, the corresponding _key_* method is called.
    """

    """'path': instance property which is used as a key for the return state.

    Whether the feature is system wide or not, the path must not contain
    any forward slash ('/').
    """
    path = ''

    """ For system wide features, watch under LEADING/global/<path>/<uuid>
    """
    is_system_wide = False

    def _configuration_key_space(self, host):
        if self.is_system_wide:
            return (mech_vpp.LEADIN + '/global/%s' % (self.path))
        else:
            return (mech_vpp.LEADIN + '/nodes/%s/%s' % (host, self.path))

    def _operational_key_space(self, host):
        return (mech_vpp.LEADIN + '/state/%s/%s' % (host, self.path))

    def _key_create(self, host, key, value):
        """Feature for host was created.

        Typically, the wanted behaviour is the same as 'set'.
        """
        self.set(host, key, value)

    @abstractmethod
    def _key_set(self, host, key, value):
        """Feature for host was set.

        This is called on creation or update for a key
        """
        pass

    @abstractmethod
    def _key_delete(self, host, key, value):
        """Feature for host was deleted.

        In this case, the value will always be 'None'.
        """
        pass

    def _key_expire(self, host, key, value):
        """Key has expired.

        Default behaviour: No action
        """
        pass

    def resync(self):
        """Resync with etcd state.

        On resync call, we must typically clean internal cached
        values as the whole tree will be read, and method '_key_set'
        will be called for each key/value pair.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class AgentFeature(ServerFeature):

    def __init__(self, host, etcd_client, vppf):
        self.host = host
        self.etcd_client = etcd_client
        self.etcd_helper = nwvpp_utils.EtcdHelper(self.etcd_client)
        self.vppf = vppf
        pass

    def tick(self):
        """Periodic method called at each watch timeout.

        Usefull to advertise current status, used only by the agent.
        """
        pass
