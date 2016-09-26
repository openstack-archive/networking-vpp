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

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class EtcdHelper(object):

    def __init__(self, client):
        self.etcd_client = client

    def recover_etcd_state(self, key_space):
        """Recover the current state of the watching keyspace.

        Etcd only keeps history of 1000 events. So if all the
        events are missed, we need to recover the keyspace by
        reading and re-starting the watch from etcd_index + 1
        """
        LOG.debug("Recovering etcd key space: %s" % key_space)
        rv = self.etcd_client.read(key_space)
        return rv.etcd_index + 1
