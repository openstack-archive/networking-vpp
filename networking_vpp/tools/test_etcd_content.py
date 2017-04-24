#!/usr/bin/python
# Copyright (c) 2016 Cisco Systems, Inc.
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

import etcd
import json
import re


from openstack import connection
conn = connection.from_config()

etcd_client = etcd.Client(port=2379)


port_paths = set()

for port in conn.network.ports():
    id = port.id

    binding_host = port.binding_host_id
    if binding_host is not None and binding_host != '':

        if port.binding_vif_type == 'binding_failed':
            print('WARN: binding failed on %s' % id)
            continue

        port_path_in_etcd = '/networking-vpp/nodes/%s/ports/%s' \
                            % (binding_host, id)
        try:
            port_paths.add(port_path_in_etcd)
            # may throw not-found
            port_in_etcd = etcd_client.read(port_path_in_etcd)

            network = conn.network.find_network(port.network_id)

            expected_data = {
                "segmentation_id": network.provider_segmentation_id,
                "mtu": network.mtu,
                "mac_address": port.mac_address,
                "network_type": network.provider_network_type,
                "physnet": network.provider_physical_network,
                "binding_type": port.binding_vif_type,
                "allowed_address_pairs": port.allowed_address_pairs,
                "fixed_ips": port.fixed_ips,
                "port_security_enabled": port.is_port_security_enabled,
                "security_groups": port.security_group_ids,
            }
            if port.ip_address is not None:
                expected_data["ip_address"] = port.ip_address,

            etcd_value = json.loads(port_in_etcd.value)
            problems = []
            for f in sorted(expected_data.keys()):
                if f in etcd_value:
                    if etcd_value[f] != expected_data[f]:
                        problems.append('key %s: %s != %s' %
                                        (f, str(etcd_value[f]),
                                         str(expected_data[f])))
                    del etcd_value[f]
                else:
                    print('WARN: port %s has no key %s=%s in etcd' %
                          (id, f, expected_data[f]))

            for f in sorted(etcd_value.keys()):
                problems.append('Key %s in etcd with value %s; unexpected' %
                                (f, str(etcd_value[f])))

            if problems:
                print('FAIL on port %s content:' % id, '; '.join(problems))
            else:
                print('OK: port %s as expected' % id)
        except etcd.EtcdKeyNotFound:
            print('WARN: port path "%s" corresponding to a bound port is '
                  'not in etcd' % port_path_in_etcd)
    else:
        print('OK: skipping unbound port %s' % id)
        # This port has not been bound, so we didn't tell the network
        # infra about it
        pass


def main():
    # Confirm only the ports we expect to find are in etcd
    keypatt = re.compile(r'i^/networking-vpp/nodes/[^/]+/ports/[^/]+$')

    result = etcd_client.read('/', recursive=True)
    for val in result.children:
        k = val.key
        res = keypatt.match(k)
        if res:
            # Only worry about key matches
            if k not in port_paths:
                print('WARN: unknown port key "%s" in etcd' % k)
            else:
                print('OK: key belongs to known port')
                port_paths.remove(k)

if __name__ == '__main__':
    main()
