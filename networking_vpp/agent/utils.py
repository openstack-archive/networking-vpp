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

import etcd
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
        except etcd.EtcdNotFile:
            # Can't delete directories - they're harmless anyway
            pass

    def ensure_dir(self, path):
        try:
            self.etcd_client.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass


class EtcdClientFactory(object):

    def _parse_host(self, etc_host_elem, default_port):
        """Parse a single etcd host entry (which can be host or host/port)

        Returns a format suitable for the etcd client creation call.
        NB: the client call is documented to take one host, host/port
        tuple or a tuple of host/port tuples; in fact, it will take
        a bare host in the tuple form as well.
        """

        if not isinstance(etc_host_elem, str) or etc_host_elem == '':
            raise vpp_agent_exec.InvalidEtcHostConfig()

        if ETC_PORT_HOST_DELIMITER in etc_host_elem:
            try:
                host, port = etc_host_elem.split(ETC_PORT_HOST_DELIMITER)
                port = int(port)
                etc_host = (host, port,)
            except ValueError:
                raise vpp_agent_exec.InvalidEtcHostConfig()
        else:
            etc_host = (etc_host_elem, default_port)

        return etc_host

    def _parse_host_config(self, etc_host, default_port):
        """Parse etcd host config (host, host/port, or list of host/port)

        Returns a format suitable for the etcd client creation call.
        This always uses the list-of-hosts tuple format, even with a single
        host.
        """

        if not isinstance(etc_host, str):
            raise vpp_agent_exec.InvalidEtcHostsConfig()

        if ETC_HOSTS_DELIMITER in etc_host:
            hosts = etc_host.split(ETC_HOSTS_DELIMITER)
        else:
            hosts = [etc_host]

        etc_hosts = ()
        for host in hosts:
            etc_hosts = etc_hosts + (self._parse_host(host, default_port),)

        return etc_hosts

    def __init__(self, ml2_vpp_conf):
        hostconf = self._parse_host_config(ml2_vpp_conf.etcd_host,
                                          ml2_vpp_conf.etcd_port)

        self.hostconf = hostconf
        self.etcd_user = ml2_vpp_conf.etcd_user
        self.etcd_pass = ml2_vpp_conf.etcd_pass

    def client(self):
        etcd_client = \
            etcd.Client(host=self.hostconf,
                        username=self.etcd_user,
                        password=self.etcd_pass,
                        allow_reconnect=True)

        return etcd_client
