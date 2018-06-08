Port mirroring support
======================

Networking vpp supports remote port mirroring. This functionality
is intended to be used for debugging and troubleshooting.

For this purpose, networking-vpp implements a driver for the extension
neutron/tap-as-a-service
(https://git.openstack.org/cgit/openstack/tap-as-a-service/).

1. Installation
- Install the neutron extension: openstack/tap-as-a-service

- Update the ml2 plugin configuration files
Add the following lines to the ML2 configuration
(likely /etc/neutron/plugins/ml2/ml2_conf.ini) on any hosts running
VPP and its agent (e.g. compute hosts):

    [ml2_vpp]
    driver_extensions = taas_driver
    vpp_agent_extensions = taas_agent

- Update the taas configuration
Add the following lines to the ML2 configuration on the Neutron server:

    [service_providers]
    service_provider = TAAS:TAAS:networking_vpp.taas_vpp.TaasEtcdDriver:default

2. Usage
See the documentation of Tap as a service
(https://git.openstack.org/cgit/openstack/tap-as-a-service/).  This
implements the standard service API.

3. Known Limitations
- Live migration is not supported by this version.
- vxlan support is currently preliminary.

