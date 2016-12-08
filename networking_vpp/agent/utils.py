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

from etcd import EtcdNotFile
from networking_vpp.agent import exceptions as vpp_agent_exec
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

ETC_HOSTS_DELIMITER = ','
ETC_PORT_HOST_DELIMITER = ':'


class EtcdHelper(object):

    def __init__(self, client):
        self.etcd_client = client

    def clear_state(self, key_space):
        """Clear the keys in the key_space"""
        LOG.debug("Clearing key space: %s", key_space)
        try:
            rv = self.etcd_client.read(key_space)
            for child in rv.children:
                self.etcd_client.delete(child.key)
        except EtcdNotFile:
            # Can't delete directories - they're harmless anyway
            pass


def parse_host_config(etc_host):
    if ETC_HOSTS_DELIMITER in etc_host:
        hosts = etc_host.split(ETC_HOSTS_DELIMITER)
        etc_hosts = ()
        for host in hosts:
            try:
                host, port = host.split(ETC_PORT_HOST_DELIMITER)
                etc_hosts = etc_hosts + ((host, port),)
            except ValueError:
                raise vpp_agent_exec.InvalidEtcHostsConfig()
        return etc_hosts
    else:
        if not etc_host:
            raise vpp_agent_exec.InvalidEtcHostConfig()
        return etc_host
