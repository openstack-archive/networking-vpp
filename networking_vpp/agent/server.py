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


# This is a simple Flask application that provides REST APIs by which
# compute and network services can communicate, plus a REST API for
# debugging using a CLI client.

# Note that it does *NOT* at this point have a persistent database, so
# restarting this process will make Gluon forget about every port it's
# learned, which will not do your system much good (the data is in the
# global 'backends' and 'ports' objects).  This is for simplicity of
# demonstration; we have a second codebase already defined that is
# written to OpenStack endpoint principles and includes its ORM, so
# that work was not repeated here where the aim was to get the APIs
# worked out.  The two codebases will merge in the future.

from flask import Flask
from flask_restful import Api
from flask_restful import reqparse
from flask_restful import Resource
import os
import distro
import sys
import vpp
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.common import constants as n_const
from networking_vpp import config_opts
from oslo_config import cfg
#from oslo_log import log as logging
import logging
import time
from threading import Thread

######################################################################

# This mirrors functionality in Neutron so that we're creating a name
# that Neutron can find for its agents.

DEV_NAME_PREFIX = n_const.TAP_DEVICE_PREFIX


def get_tap_name(uuid):
    return n_const.TAP_DEVICE_PREFIX + uuid[0:11]

# This mirrors functionality in Nova so that we're creating a vhostuser
# name that it will be able to locate

VHOSTUSER_DIR = '/tmp'


def get_vhostuser_name(uuid):
    return os.path.join(VHOSTUSER_DIR, uuid)


def get_distro_family():
    if distro.id() in ['rhel', 'centos', 'fedora']:
        return 'redhat'
    else:
        return distro.id()


def get_qemu_default():
    # TODO(ijw): this should be moved to the devstack code
    distro = get_distro_family()
    if distro == 'redhat':
        qemu_user = 'qemu'
        qemu_group = 'qemu'
    elif distro == 'ubuntu':
        qemu_user = 'libvirt-qemu'
        qemu_group = 'kvm'
    else:
        # let's just try libvirt-qemu for now, maybe we should instead
        # print error messsage and exit?
        qemu_user = 'libvirt-qemu'
        qemu_group = 'kvm'

    return (qemu_user, qemu_group)


######################################################################


class VPPForwarder(object):

    def __init__(self, log,
                 flat_network_if=None,
                 vlan_trunk_if=None,
                 vxlan_src_addr=None,
                 vxlan_bcast_addr=None,
                 vxlan_vrf=None,
                 qemu_user=None,
                 qemu_group=None):
        self.vpp = vpp.VPPInterface(log)

        self.qemu_user = qemu_user
        self.qemu_group = qemu_group

        # This is the list of flat network interfaces for providing FLAT networking
        self.flat_if = flat_network_if.split(',')
        self.active_ifs = set() #set of used interfaces for flat networking

        # This is the trunk interface for VLAN networking
        self.trunk_if = vlan_trunk_if

        # This is the address we'll use if we plan on broadcasting
        # vxlan packets
        self.vxlan_bcast_addr = vxlan_bcast_addr
        self.vxlan_src_addr = vxlan_src_addr
        self.vxlan_vrf = vxlan_vrf

        # Used as a unique number for bridge IDs
        self.next_bridge_id = 5678

        # TODO(ijw): these things want preserving over a daemon restart.
        self.networks = {}      # vlan: bridge index
        self.interfaces = {}    # uuid: if idx
        self.nets = {}

        # TODO (najoy) removing cleanups - should fetch data from the neutron server and see
        # if the interface is being used
        # for (ifname, f) in self.vpp.get_interfaces():
        #     # Clean up interfaces from previous runs
        #     # TODO(ijw) can't easily SPOT VLAN subifs to delete
        #     if ifname.startswith('tap-'):
        #         # all VPP tap interfaces are of this form
        #         self.vpp.delete_tap(f.sw_if_index)
        #     elif ifname.startswith('VirtualEthernet'):
        #         # all VPP vhostuser interfaces are of this form
        #         self.vpp.delete_vhostuser(f.sw_if_index)


        # trunk_ifstruct = self.vpp.get_interface(self.trunk_if) if self.trunk_if else None
        #flat_ifstruct = self.vpp.get_interface(self.flat_if) if self.flat_if else None
      #   if trunk_ifstruct is None and flat_ifstruct is None:
                   # raise Exception("Could not find a VPP uplink interface:%s" % self.trunk_if or self.flat_if)
      #   if trunk_ifstruct is not None:
      #       self.trunk_ifidx = trunk_ifstruct.sw_if_index
      #       # This interface is not automatically up just because
      #       # we've started and we need to ensure it is before
      #       # proceeding.

      #       # TODO(ijw): when we start up in a recovery mode we may
      #       # want to check the local VPP config and bring it up when
      #       # confirmed.
      #       app.logger.debug("Activating VPP's Vlan trunk interface: %s" % self.trunk_if)
      #       self.vpp.ifup(self.trunk_ifidx)
        # if flat_ifstruct is not None:
        #     self.flat_ifidx = flat_ifstruct.sw_if_index
        #     app.logger.debug("Activating VPP's Flat network interface: %s" % self.flat_if)
        #     self.vpp.ifup(self.flat_ifidx)

    def get_flat_interface(self):
        """ Return the next available interface for flat networking """
        interface = None
        for intf in self.flat_if:
            if intf not in self.active_ifs:
                app.logger.debug("Using interface:%s for flat networking" % intf)
                interface = intf
                break
        return interface

    def get_trunk_interface(self):
        """ Return the trunk interface for VLAN networking """
        #TODO(najoy) Return the trunk interface corresponding to the physical network mapping
        intf = self.trunk_if if self.trunk_if else None
        if intf:
            app.logger.debug("Using trunk interface:%s for VLAN networking" % intf)
        return intf

    def get_vpp_ifidx(self, if_name):
        """ Return VPP's interface index value for the network interface"""
        return self.vpp.get_interface(if_name).sw_if_index

    # This, here, is us creating a FLAT, VLAN or VxLAN backed network
    def network_on_host(self, net_uuid, net_type=None, seg_id=None, net_name=None):
        if net_uuid not in self.nets:
            #if (net_type, seg_id) not in self.networks:
            # TODO(ijw): bridge domains have no distinguishing marks.
            # VPP needs to allow us to name or label them so that we
            # can find them when we restart
            if net_type == 'flat':
                intf = self.get_flat_interface()
                #TODO(najoy): Need to send a return value so the ML2 driver can raise an exception and prevent
                #network creation
                if intf is None:
                    app.logger.error("Error: creating network as a flat network interface is not available")
                    return {}
                if_upstream = self.get_vpp_ifidx(intf)
                #if_upstream = self.flat_ifidx
                app.logger.debug('Adding upstream interface-indx:%s-%s to bridge for flat networking' % (intf, if_upstream))
                self.active_ifs.add(intf)
            elif net_type == 'vlan':
                # TODO(ijw): this VLAN subinterface may already exist, and
                # may even be in another bridge domain already (see
                # above).
                intf = self.get_trunk_interface()
                if intf is None:
                    app.logger.error("Error: creating network as a trunk network interface is not available")
                    return {}
                trunk_ifidx = self.get_vpp_ifidx(intf)
                app.logger.debug("Activating VPP's Vlan trunk interface: %s" % intf)
                self.vpp.ifup(trunk_ifidx)
                if_upstream = self.vpp.create_vlan_subif(trunk_ifidx,
                                                         seg_id)
                app.logger.debug('Adding upstream trunk interface:%s.%s \
                to bridge for vlan networking' % (intf, seg_id))
            # elif net_type == 'vxlan':
            #     if_upstream = \
            #         self.vpp.create_srcrep_vxlan_subif(self, self.vxlan_vrf,
            #                                            self.vxlan_src_addr,
            #                                            self.vxlan_bcast_addr,
            #                                            seg_id)
            else:
                raise Exception('network type %s not supported', net_type)

            self.vpp.ifup(if_upstream)
            # May not remain this way but we use the VLAN ID as the
            # bridge ID; TODO(ijw): bridge ID can already exist, we
            # should check till we find a free one
            id = self.next_bridge_id
            self.next_bridge_id += 1
            self.vpp.create_bridge_domain(id)
            self.vpp.add_to_bridge(id, if_upstream)
            #self.networks[(net_type, seg_id)] = id
            self.nets[net_uuid] = {
                               'bridge_domain_id': id,
                               'if_upstream': intf,
                               'if_upstream_idx': if_upstream,
                               'network_type': net_type,
                               'segmentation_id': seg_id,
                               'network_name' : net_name
                                  }
            app.logger.debug('Created network UUID:%s-%s' % (net_uuid, self.nets[net_uuid]))
        return self.nets[net_uuid]
        #return self.networks[(type, seg_id)]

    ########################################
    # stolen from LB driver
    def _bridge_exists_and_ensure_up(self, bridge_name):
        """Check if the bridge exists and make sure it is up."""
        br = ip_lib.IPDevice(bridge_name)
        br.set_log_fail_as_error(False)
        try:
            # If the device doesn't exist this will throw a RuntimeError
            br.link.set_up()
        except RuntimeError:
            return False
        return True

    def ensure_bridge(self, bridge_name):
        """Create a bridge unless it already exists."""
        # _bridge_exists_and_ensure_up instead of device_exists is used here
        # because there are cases where the bridge exists but it's not UP,
        # for example:
        # 1) A greenthread was executing this function and had not yet executed
        # "ip link set bridge_name up" before eventlet switched to this
        # thread running the same function
        # 2) The Nova VIF driver was running concurrently and had just created
        #    the bridge, but had not yet put it UP
        if not self._bridge_exists_and_ensure_up(bridge_name):
            bridge_device = bridge_lib.BridgeDevice.addbr(bridge_name)
            if bridge_device.setfd(0):
                return
            if bridge_device.disable_stp():
                return
            if bridge_device.disable_ipv6():
                return
            if bridge_device.link.set_up():
                return
        else:
            bridge_device = bridge_lib.BridgeDevice(bridge_name)
        return bridge_device

    # end theft
    ########################################

    ##TODO(njoy): make wait_time configurable
    def add_external_tap(self, device_name, bridge, bridge_name):
        """
        Wait for the external tap device to be created by the DHCP agent.
        When the tap device is ready, add it to bridge
        Run as a thread so REST call can return before this code completes its execution
        """
        wait_time = 60
        found = False
        while wait_time > 0:
            if ip_lib.device_exists(device_name):
                app.logger.debug('External tap device %s found!' % device_name)
                app.logger.debug('Bridging tap interface %s on %s' % (device_name, bridge_name))
                if not bridge.owns_interface(device_name):
                    bridge.addif(device_name)
                else:
                    app.logger.debug('Interface: %s is already added to the bridge %s' %
                        (device_name, bridge_name))
                found = True
                break
            else:
                #app.logger.debug('Waiting for external tap device %s to be created' % device_name)
                time.sleep(2)
                wait_time -= 2
        if not found:
            app.logger.error('Failed waiting for external tap device:%s' % device_name)


    def create_interface_on_host(self, if_type, uuid, mac):
        if uuid in self.interfaces:
            app.logger.debug('port %s repeat binding request - ignored' % uuid)
        else:
            app.logger.debug('binding port %s as type %s' % (uuid, if_type))

            # TODO(ijw): naming not obviously consistent with
            # Neutron's naming
            name = uuid[0:11]
            bridge_name = 'br-' + name
            tap_name = 'tap' + name

            if if_type == 'maketap' or if_type == 'plugtap':
                if if_type == 'maketap':
                    iface = self.vpp.create_tap(tap_name, mac)
                    props = {'bind_type': 'maketap', 'name': tap_name}
                else:
                    int_tap_name = 'vpp' + name
                    props = {'bind_type': 'plugtap',
                             'bridge_name': bridge_name,
                             'ext_tap_name': tap_name,
                             'int_tap_name': int_tap_name
                    }
                    app.logger.debug('Creating tap interface %s with mac %s' % (int_tap_name, mac))

                    iface = self.vpp.create_tap(int_tap_name, mac)
                    # TODO(ijw): someone somewhere ought to be sorting
                    # the MTUs out
                    br = self.ensure_bridge(bridge_name)
                    # This is the external TAP device that will be created by an agent, say the DHCP agent later in time
                    t = Thread(target=self.add_external_tap, args=(tap_name, br, bridge_name,))
                    t.start()
                    # This is the device that we just created with VPP
                    if not br.owns_interface(int_tap_name):
                        br.addif(int_tap_name)
            elif if_type == 'vhostuser':
                path = get_vhostuser_name(uuid)
                iface = self.vpp.create_vhostuser(path, mac, self.qemu_user,
                                                  self.qemu_group)
                props = {'bind_type': 'vhostuser', 'path': uuid}
            else:
                raise Exception('unsupported interface type')

            self.interfaces[uuid] = (iface, props)
        return self.interfaces[uuid]

    def bind_interface_on_host(self, uuid, if_type, mac, net_type, seg_id, net_id):
        net_br_idx = self.network_on_host(net_id)['bridge_domain_id']

        (iface_idx, props) = self.create_interface_on_host(if_type, uuid, mac)
        self.vpp.ifup(iface_idx)
        self.vpp.add_to_bridge(net_br_idx, iface_idx)
        return props

    def unbind_interface_on_host(self, uuid, if_type):
        if uuid not in self.interfaces:
            app.logger.debug("unknown port %s unbinding request - ignored" % uuid)
        else:
            iface_idx, props = self.interfaces[uuid]

            if if_type != props['bind_type']:
                app.logger.error("Incorrect unbinding port type:%s request received" % if_type)
                app.logger.error("Expected type:%s, Received Type:%s" % (props['bind_type'], if_type))
                return 1

            app.logger.debug("unbinding port %s, recorded as type %s" % (uuid, props['bind_type']))

            # We no longer need this interface.  Specifically if it's
            # a vhostuser interface it's annoying to have it around
            # because the VM's memory (hugepages) will not be
            # released.  So, here, we destroy it.

            # TODO(ijw): I'm assuming deleting an interface in a
            # bridge domain works...
            if props['bind_type'] == 'vhostuser':
                self.vpp.delete_vhostuser(iface_idx)
            elif props['bind_type'] in ['maketap', 'plugtap']:
                self.vpp.delete_tap(iface_idx)
                if props['bind_type'] == 'plugtap':
                    name = uuid[0:11]
                    bridge_name = 'br-' + name

                    bridge = bridge_lib.BridgeDevice(bridge_name)
                    if bridge.exists():
                        # These may fail, don't care much
                        try:
                            if bridge.owns_interface(props['int_tap_name']):
                                bridge.delif(props['int_tap_name'])
                            if bridge.owns_interface(props['ext_tap_name']):
                                bridge.delif(props['ext_tap_name'])
                            bridge.link.set_down()
                            bridge.delbr()
                        except Exception as exc:
                            app.logger.debug(exc)

            else:
                app.logger.error('Unknown port type %s during unbind' % props['bind_type'])


######################################################################

class PortBind(Resource):
    bind_args = reqparse.RequestParser()
    bind_args.add_argument('mac_address', type=str, required=True)
    bind_args.add_argument('mtu', type=str, required=True)
    bind_args.add_argument('segmentation_id', type=int, required=True)
    bind_args.add_argument('network_type', type=str, required=True)
    bind_args.add_argument('host', type=str, required=True)
    bind_args.add_argument('binding_type', type=str, required=True)
    bind_args.add_argument('network_id', type=str, required=True)

    def __init(self, *args, **kwargs):
        super('PortBind', self).__init__(*args, **kwargs)

    def put(self, id):
        id=str(id)  # comes in as unicode

        global vppf
        args = self.bind_args.parse_args()
        app.logger.debug("on host %s, binding %s %d to mac %s id %s as binding_type %s"
                         "on network %s"
                         % (args['host'],
                            args['network_type'],
                            args['segmentation_id'],
                            args['mac_address'],
                            id,
                            args['binding_type'],
                            args['network_id'])
                         )
        if args['binding_type'] in 'vhostuser':
            app.logger.debug('Creating a vhostuser port:%s binding on host %s' % (id, args['host']))
            vppf.bind_interface_on_host('vhostuser',
                                     id,
                                     args['mac_address'],
                                     args['network_type'],
                                     args['segmentation_id'],
                                     args['network_id']
                                     )
        elif args['binding_type'] in 'plugtap':
            app.logger.debug('Creating a plugtap port:%s binding on host %s' % (id, args['host']))
            vppf.bind_interface_on_host('plugtap',
                                    id,
                                    args['mac_address'],
                                    args['network_type'],
                                    args['segmentation_id'],
                                    args['network_id']
                                    )
        else:
            app.logger.error('Unsupported binding type :%s requested' % args['binding_type'])


class PortUnbind(Resource):
    bind_args = reqparse.RequestParser()
    bind_args.add_argument('host', type=str, required=True)
    bind_args.add_argument('binding_type', type=str, required=True)

    def __init__(self, *args, **kwargs):
        super('PortUnbind', self).__init__(*args, **kwargs)

    def put(self, id, host):
        id=str(id)  # comes in as unicode

        global vppf

        args = self.bind_args.parse_args()
        app.logger.debug('on host %s, unbinding port ID:%s with binding_type:%s'
                         % (args['host'],
                            id,
                            args['binding_type'])
                         )
        vppf.unbind_interface_on_host(id, args['binding_type'])

class Network(Resource):
    bind_args = reqparse.RequestParser()
    bind_args.add_argument('physical_network', type=str, required=True)
    bind_args.add_argument('network_type', type=str, required=True)
    bind_args.add_argument('segmentation_id', type=str, required=True)
    bind_args.add_argument('name', type=str, required=True)

    def __init(self, *args, **kwargs):
        super('Network', self).__init__(*args, **kwargs)

    def post(self, id):
        global vppf
        args = self.bind_args.parse_args()
        app.logger.debug("Create network ID:%s name:%s"
                         " with network_type:%s and seg_id:%s"
                         % (id,
                            args['name'],
                            args['network_type'],
                            args['segmentation_id']
                            )
                         )
        vppf.network_on_host(id, args['network_type'], args['segmentation_id'], args['name'])
    def put(self, id):
        global vppf
        args = self.bind_args.parse_args()
        app.logger.debug("Update network ID:%s name:%s"
                         " with network_type:%s and seg_id:%s"
                         % (id,
                            args['name'],
                            args['network_type'],
                            args['segmentation_id']
                            )
                         )

    def delete(self, id):
        global vppf
        args = self.bind_args.parse_args()
        app.logger.debug("Delete network ID:%s name:%s"
                         " with network_type:%s and seg_id:%s"
                         % (id,
                            args['name'],
                            args['network_type'],
                            args['segmentation_id']
                            )
                         )


# Basic Flask RESTful app setup with logging
app = Flask('vpp-agent')
app.debug = True
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')
ch.setFormatter(formatter)
app.logger.addHandler(ch)
app.logger.debug('Debug logging enabled')

def main():
    # If the user and/or group are specified in config file, we will use
    # them as configured; otherwise we try to use defaults depending on
    # distribution. Currently only supporting ubuntu and redhat.
    qemu_user = cfg.CONF.ml2_vpp.qemu_user
    qemu_group = cfg.CONF.ml2_vpp.qemu_group
    default_user, default_group = get_qemu_default()
    if not qemu_user:
        qemu_user = default_user
    if not qemu_group:
        qemu_group = default_group

    cfg.CONF(sys.argv[1:])
    global vppf
    vppf = VPPForwarder(app.logger,
                        flat_network_if=cfg.CONF.ml2_vpp.flat_network_if,
                        vlan_trunk_if=cfg.CONF.ml2_vpp.vlan_trunk_if,
                        vxlan_src_addr=cfg.CONF.ml2_vpp.vxlan_src_addr,
                        vxlan_bcast_addr=cfg.CONF.ml2_vpp.vxlan_bcast_addr,
                        vxlan_vrf=cfg.CONF.ml2_vpp.vxlan_vrf,
                        qemu_user=qemu_user,
                        qemu_group=qemu_group)
    api = Api(app)
    api.add_resource(PortBind, '/ports/<id>/bind')
    api.add_resource(PortUnbind, '/ports/<id>/unbind')
    api.add_resource(Network, '/networks/<id>')
    app.logger.debug("Starting VPP agent on host address: 0.0.0.0 and port 2704")
    app.run(host='0.0.0.0',port=2704)


if __name__ == '__main__':
    main()
