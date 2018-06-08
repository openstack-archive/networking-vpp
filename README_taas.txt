Port mirroring support
======================

Networking vpp supports remote port mirroring. This functionality is intended to be used for debugging and troubleshooting. 

For this purpose, networking-vpp implements a driver for the extension neutron/tap-as-a-service
(https://git.openstack.org/cgit/openstack/tap-as-a-service/)

1/ Installation
- Install the neutron extension: openstack/tap-as-a-service

- Update the ml2 plugin configuration files
Add the following lines in the configuration file /etc/neutron/plugins/ml2/ml2_conf.ini
	[ml2_vpp]
	driver_extensions = taas_driver
	vpp_agent_extensions = taas_agent

- Update the taas configuration file
Add the following lines in the configuration file /etc/neutron/taas_plugin.ini
[service_providers]
service_provider = TAAS:TAAS:networking_vpp.taas_vpp.TaasEtcdDriver:default



2/ Usage
See the documentation of Tap as a service (https://git.openstack.org/cgit/openstack/tap-as-a-service/)

3/ Known Limitations
Live migration is not supported by this version.

