#!/usr/bin/python

import etcd
import json
import re
import os
import pprint


from openstack import connection
conn = connection.from_config()

etcd_client = etcd.Client(port=2379)

def printobj(obj):
   print 'Class:', type(obj).__name__
   pprint.pprint(obj.__dict__)
   print ''

port_paths=set()

for port in conn.network.ports():
    id = port.id

    binding_host = port.binding_host_id
    if binding_host is not None:

	try:
	    port_path_in_etcd = '/networking-vpp/nodes/%s/ports/%s' % (binding_host, id)
	    port_paths.add(port_path_in_etcd)
	    port_in_etcd = etcd_client.read(port_path_in_etcd) # may throw not-found

	    network = conn.network.find_network(port.network_id)

	    expected_data = {
		"segmentation_id": network.provider_segmentation_id,
		"mtu": network.mtu,
		"mac_address": port.mac_address,
		"network_type": network.provider_network_type,
		"physnet": network.provider_physical_network,
		"binding_type": port.binding_vif_type
	    }
	    etcd_value=json.loads(port_in_etcd.value)
	    problems=[]
            for f in sorted(expected_data.keys()):
		if f in etcd_value:
		    if etcd_value[f] != expected_data[f]:
			problems.append('key %s: %s != %s' % (f, str(etcd_value[f]), str(expected_data[f])))
		    del etcd_value[f]
		else:
		    print 'WARN: port %s has no key %s=%s in etcd' % (id, f, expected_data[f])

	    for f in sorted(etcd_value.keys()):
		problems.append('Key %s in etcd with value %s; unexpected' % (f, str(etcd_value[f])))
		printobj(port)

	    if problems:
		print 'FAIL on port %s content:' % id, '; '.join(problems)
	    else:
		print 'OK: port %s as expected' % id
	except etcd.EtcdKeyNotFound:
	    print 'WARN: port path "%s" corresponding to a bound port is not in etcd'
    else:
	print 'OK: skipping unbound port %s' % id
	# This port has not been bound, so we didn't tell the network infra about it
	pass

# Confirm only the ports we expect to find are in etcd
keypatt = re.compile(r'i^/networking-vpp/nodes/[^/]+/ports/[^/]+$')

result = etcd_client.read('/', recursive=True)
for val in result.children:
    k = val.key
    res = keypatt.match(k)
    if res:
	# Only worry about key matches
	if k not in port_paths:
	    print 'WARN: unknown port key "%s" in etcd' % k
	else:
	    print 'OK: key belongs to known port'
	    port_paths.remove(k)
