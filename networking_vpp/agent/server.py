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

# Note that it does *NOT* at this point have a persistent database, so
# restarting this process will make Gluon forget about every port it's
# learned, which will not do your system much good (the data is in the
# global 'backends' and 'ports' objects).  This is for simplicity of
# demonstration; we have a second codebase already defined that is
# written to OpenStack endpoint principles and includes its ORM, so
# that work was not repeated here where the aim was to get the APIs
# worked out.  The two codebases will merge in the future.

import etcd
import eventlet
import json
import os
import re
import sys
import threading
import time
import vpp

from networking_vpp.agent import utils as nwvpp_utils
from networking_vpp import compat
from networking_vpp.compat import n_const
from networking_vpp import config_opts
from networking_vpp.etcdutils import EtcdWatcher
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


# config_opts is required to configure the options within it, but
# not referenced from here, so shut up tox:
assert config_opts

eventlet.monkey_patch()

######################################################################

# This mirrors functionality in Neutron so that we're creating a name
# that Neutron can find for its agents.

DEV_NAME_PREFIX = n_const.TAP_DEVICE_PREFIX

# Apply monkey patch if necessary
compat.monkey_patch()


def get_tap_name(uuid):
    return n_const.TAP_DEVICE_PREFIX + uuid[0:11]


def get_vhostuser_name(uuid):
    return os.path.join(cfg.CONF.ml2_vpp.vhost_user_dir, uuid)


######################################################################


class UnsupportedInterfaceException(Exception):
    pass


class VPPForwarder(object):

    def __init__(self,
                 physnets,  # physnet_name: interface-name
                 vxlan_src_addr=None,
                 vxlan_bcast_addr=None,
                 vxlan_vrf=None):
        self.vpp = vpp.VPPInterface(LOG)

        self.physnets = physnets

        # This is the address we'll use if we plan on broadcasting
        # vxlan packets
        self.vxlan_bcast_addr = vxlan_bcast_addr
        self.vxlan_src_addr = vxlan_src_addr
        self.vxlan_vrf = vxlan_vrf

        self.networks = {}      # (physnet, type, ID): datastruct
        self.interfaces = {}    # uuid: if idx

        # key: sw if index in VPP; present when vhost-user is
        # connected and removed when we delete things.  May accumulate
        # any other VPP interfaces too, but that's harmless.
        self.iface_connected = set()

        self.vhost_ready_callback = None
        cb_event = self.vpp.CallbackEvents.VHOST_USER_CONNECT
        self.vpp.register_for_events(cb_event, self._vhost_ready_event)

    ########################################

    def _vhost_ready_event(self, iface):
        """Callback from VPP interface on vhostuser socket connection"""

        # TODO(ijw): messy and a bit specific to the VPP interface -
        # shouldn't be returning the API datastructure?
        LOG.debug("vhost online: %s", str(iface))
        self._notify_connected(iface.sw_if_index)

    def _notify_connected(self, sw_if_index):
        """Deal with newly active interfaces noticed by VPP

        Any interface that has been created and has also been
        connected to goes into the up state.  At this point, we can
        safely say that the VM is ready for traffic passing.

        When interacting with Nova, this usually indicates that the VM
        has been created and the vhost-user connection made.  We
        should send the notification only after the port has been
        created and the hypervisor has attached to it.  (You have to
        create the interface to be attached to but this checks for
        the data that's written on creation to be ready to avoid
        a race condition.)

        We may send multiple notifications to Nova if an interface
        disconnects and reconnects - this is harmless.
        """
        self.iface_connected.add(sw_if_index)

        if self.vhost_ready_callback:
            self.vhost_ready_callback(sw_if_index)

    def vhostuser_linked_up(self, sw_if_index):
        return sw_if_index in self.iface_connected

    ########################################

    def get_if_for_physnet(self, physnet):
        ifname = self.physnets.get(physnet, None)
        if ifname is None:
            LOG.error('Physnet %s requested but not in config',
                      physnet)
            return None, None
        ifidx = self.vpp.get_ifidx_by_name(ifname)
        if ifname is None:
            LOG.error('Physnet %s interface %s does not '
                      'exist in VPP', ifname)
            return None, None
        return ifname, ifidx

    def network_on_host(self, physnet, net_type, seg_id=None):
        """Find or create a network of the type required"""

        if (physnet, net_type, seg_id) not in self.networks:
            self.create_network_on_host(physnet, net_type, seg_id)
        return self.networks.get((physnet, net_type, seg_id), None)

    def create_network_on_host(self, physnet, net_type, seg_id):
        intf, ifidx = self.get_if_for_physnet(physnet)
        if intf is None:
            return None

        # TODO(ijw): bridge domains have no distinguishing marks.
        # VPP needs to allow us to name or label them so that we
        # can find them when we restart.  If we add an interface
        # to two bridges that will likely not do as required

        if net_type == 'flat':
            if_upstream = ifidx

            LOG.debug('Adding upstream interface-idx:%s-%s to bridge '
                      'for flat networking', intf, if_upstream)

        elif net_type == 'vlan':
            self.vpp.ifup(ifidx)

            LOG.debug('Adding upstream VLAN interface %s.%s '
                      'to bridge for vlan networking', intf, seg_id)
            if_upstream = self.vpp.get_ifidx_by_name('%s.%s' % (intf, seg_id))
            if if_upstream is None:
                if_upstream = self.vpp.create_vlan_subif(ifidx,
                                                         seg_id)
        # elif net_type == 'vxlan':
        #     # NB physnet not really used here
        #     if_upstream = \
        #         self.vpp.create_srcrep_vxlan_subif(self, self.vxlan_vrf,
        #                                            self.vxlan_src_addr,
        #                                            self.vxlan_bcast_addr,
        #                                            seg_id)
        else:
            raise Exception('network type %s not supported', net_type)

        self.vpp.ifup(if_upstream)
        self.vpp.set_interface_tag(if_upstream,
                                   'openstack.%s.%s' % (net_type, seg_id))

        # Our bridge IDs have one upstream interface in so we simply use
        # that ID as their domain ID

        bridge_domains = self.vpp.get_ifaces_in_bridge_domains()
        if if_upstream not in bridge_domains:
            self.vpp.create_bridge_domain(if_upstream)

        if if_upstream not in bridge_domains.get(if_upstream, []):
            # Out bridge IDs have one upstream interface in so we simply use
            # that ID as their domain ID
            self.vpp.add_to_bridge(if_upstream, if_upstream)

        self.networks[(physnet, net_type, seg_id)] = {
            'bridge_domain_id': if_upstream,
            'if_upstream': intf,
            'if_upstream_idx': if_upstream,
            'network_type': net_type,
            'segmentation_id': seg_id,
            'physnet': physnet,
        }

    def delete_network_on_host(self, physnet, net_type, seg_id=None):
        net = self.networks.get((physnet, net_type, seg_id), None)
        if net is not None:

            self.vpp.delete_bridge_domain(net['bridge_domain_id'])
            if net['network_type'] == 'vlan':
                ifidx = self.vpp.get_ifidx_by_name(net['if_upstream']
                                                   + '.' + str(seg_id))
                self.vpp.delete_vlan_subif(ifidx)

            self.networks.pop((physnet, net_type, seg_id))
        else:
            LOG.warning("Delete Network: network is unknown to agent")

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

        # TODO(ijw): should be checking this all succeeded

    # end theft
    ########################################

    # TODO(njoy): make wait_time configurable
    # TODO(ijw): needs to be one thread for all waits
    def add_external_tap(self, device_name, bridge, bridge_name):
        """Add an externally created TAP device to the bridge

        Wait for the external tap device to be created by the DHCP agent.
        When the tap device is ready, add it to bridge Run as a thread
        so REST call can return before this code completes its
        execution.

        """
        wait_time = 60
        found = False
        while wait_time > 0:
            if ip_lib.device_exists(device_name):
                LOG.debug('External tap device %s found!',
                          device_name)
                LOG.debug('Bridging tap interface %s on %s',
                          device_name, bridge_name)
                if not bridge.owns_interface(device_name):
                    bridge.addif(device_name)
                else:
                    LOG.debug('Interface: %s is already added '
                              'to the bridge %s',
                              device_name, bridge_name)
                found = True
                break
            else:
                time.sleep(2)
                wait_time -= 2
        if not found:
            LOG.error('Failed waiting for external tap device:%s',
                      device_name)

    def _ensure_kernelside_plugtap(self, bridge_name, tap_name, int_tap_name):
        # This is the kernel-side config (and we should not assume
        # that, just because the interface exists in VPP, it has
        # been done previously - the crash could occur in the
        # middle of the process)
        # Running it twice is harmless.  Never running it is
        # problematic.

        # TODO(ijw): someone somewhere ought to be sorting
        # the MTUs out
        br = self.ensure_bridge(bridge_name)
        # This is the external TAP device that will be
        # created by an agent, say the DHCP agent later in
        # time
        t = threading.Thread(target=self.add_external_tap,
                             args=(tap_name, br, bridge_name,))
        t.start()
        # This is the device that we just created with VPP
        if not br.owns_interface(int_tap_name):
            br.addif(int_tap_name)

    def create_interface_on_host(self, if_type, uuid, mac):
        if uuid in self.interfaces:
            props = self.interfaces[uuid]
            if 'wants_verification' in props:
                del props['wants_verification']
                # TODO(cfontaine): we will want to check the configuration
                if if_type == 'plugtap':
                    LOG.debug('plugtap %s binding after resync '
                              'enforce kernel conf.', uuid)
                    self._ensure_kernelside_plugtap(props['bridge_name'],
                                                    props['ext_tap_name'],
                                                    props['int_tap_name'])
                else:
                    LOG.debug('port %s repeat binding request'
                              ' after resync - ignored', uuid)
            else:
                LOG.debug('port %s repeat binding request - ignored', uuid)

        else:
            LOG.debug('binding port %s as type %s',
                      uuid, if_type)

            # TODO(ijw): naming not obviously consistent with
            # Neutron's naming
            name = uuid[0:11]
            tap_name = 'tap' + name

            if if_type == 'maketap':
                props = {'name': tap_name}
            elif if_type == 'plugtap':
                bridge_name = 'br-' + name
                int_tap_name = 'vpp' + name

                props = {'bridge_name': bridge_name,
                         'ext_tap_name': tap_name,
                         'int_tap_name': int_tap_name}
            elif if_type == 'vhostuser':
                path = get_vhostuser_name(uuid)
                props = {'path': path}
            else:
                raise UnsupportedInterfaceException(
                    'unsupported interface type')

            props['bind_type'] = if_type
            props['mac'] = mac

            iface_idx = self.vpp.get_ifidx_by_tag(uuid)
            if iface_idx is not None:
                # The agent has at some point reset, but before the reset
                # this interface was at least created

                # TODO(ijw): we should resync by populating
                # self.interfaces() at startup from VPP, which means
                # this code would never be needed.
                # TODO(ijw): this also has the issue that - while the interface
                # now definitely exists - we don't check its type is correct.

                LOG.debug('port %s syncing with port in VPP',
                          uuid)

            else:
                LOG.debug('binding port %s as type %s' %
                          (uuid, if_type))

                if if_type == 'maketap':
                    iface_idx = self.vpp.create_tap(tap_name, mac, uuid)
                elif if_type == 'plugtap':
                    iface_idx = self.vpp.create_tap(int_tap_name, mac, uuid)
                elif if_type == 'vhostuser':
                    iface_idx = self.vpp.create_vhostuser(path, mac, uuid)

                props['iface_idx'] = iface_idx

            if if_type == 'plugtap':
                self._ensure_kernelside_plugtap(bridge_name,
                                                tap_name,
                                                int_tap_name)

            props['iface_idx'] = iface_idx

        return self.interfaces[uuid]

    def bind_interface_on_host(self, if_type, uuid, mac, physnet,
                               net_type, seg_id):
        # TODO(najoy): Need to send a return value so the ML2 driver
        # can raise an exception and prevent network creation (when
        # network_on_host returns None)

        net_data = self.network_on_host(physnet, net_type, seg_id)
        net_br_idx = net_data['bridge_domain_id']
        props = self.create_interface_on_host(if_type, uuid, mac)
        iface_idx = props['iface_idx']
        self.vpp.ifup(iface_idx)
        self.vpp.add_to_bridge(net_br_idx, iface_idx)
        props['net_data'] = net_data
        LOG.debug('Bound vpp interface with sw_idx:%s on '
                  'bridge domain:%s',
                  iface_idx, net_br_idx)
        return props

    def unbind_interface_on_host(self, uuid):
        if uuid not in self.interfaces:
            LOG.debug('unknown port %s unbinding request - ignored',
                      uuid)

            # TODO(ijw): if we're out of sync we still need to check
            # VPP for cleanups
        else:
            props = self.interfaces[uuid]
            iface_idx = props['iface_idx']

            LOG.debug('unbinding port %s, recorded as type %s',
                      uuid, props['bind_type'])

            # We no longer need this interface.  Specifically if it's
            # a vhostuser interface it's annoying to have it around
            # because the VM's memory (hugepages) will not be
            # released.  So, here, we destroy it.

            if props['bind_type'] == 'vhostuser':
                # remove port from bridge (sets to l3 mode) prior to deletion
                self.vpp.delete_from_bridge(iface_idx)
                self.vpp.delete_vhostuser(iface_idx)
            elif props['bind_type'] in ['maketap', 'plugtap']:
                # remove port from bridge (sets to l3 mode) prior to deletion
                self.vpp.delete_from_bridge(iface_idx)
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
                            LOG.debug(exc)
            else:
                LOG.error('Unknown port type %s during unbind',
                          props['bind_type'])
            self.interfaces.pop(uuid)

            # This interface is no longer connected if it's deleted
            self.iface_connected.remove(iface_idx)

            # Check if this is the last interface on host
            for interface in self.interfaces.values():
                if props['net_data'] == interface['net_data']:
                    break
            else:
                # Network is not used on this host, delete it
                net = props['net_data']
                self.delete_network_on_host(net['physnet'],
                                            net['network_type'],
                                            net['segmentation_id'])

    def read_vpp_state(self):
        """Read VPP interfaces and networks current config.

        Called on resync_start, this method rebuilds the internal
        cache for the interfaces and networks.
        """
        self.networks = {}
        self.interfaces = {}

        uuid_check = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
                                '-[0-9a-f]{4}-[0-9a-f]{12}')

        # Read interfaces configuration
        vpp_interfaces = [iface for iface in self.vpp.get_interfaces()]
        for iface in vpp_interfaces:
            LOG.debug('Processing port %s', str(iface))
            # all interfaces created by the agent do have a UUID
            if uuid_check.match(iface['tag']):
                uuid = iface['tag']
                props = {}
                if iface['name'].startswith('VirtualEthernet0/0/'):
                    path = get_vhostuser_name(uuid)
                    props['path'] = path
                    props['bind_type'] = 'vhostuser'
                else:
                    name = uuid[0:11]
                    bridge_name = 'br-' + name
                    tap_name = 'tap' + name

                    if self._bridge_exists_and_ensure_up(bridge_name):
                        int_tap_name = 'vpp' + name
                        props['bind_type'] = 'plugtap'
                        props['bridge_name'] = bridge_name
                        props['ext_tap_name'] = tap_name
                        props['int_tap_name'] = int_tap_name
                    else:
                        props['name'] = tap_name
                        props['bind_type'] = 'maketap'

                props['iface_idx'] = iface['sw_if_idx']
                props['mac'] = iface['mac']

                # Indicate that this information has been read from vpp
                # as we may want to fixup the configuratoin later
                props['wants_verification'] = True
                self.interfaces[uuid] = props
                LOG.info('new port %s found in vpp: %s', uuid, str(props))

            # Physical ifaces bound by the agent do have tag
            elif iface['tag'].startswith('openstack'):
                m = re.match('openstack.([a-z]*).([0-9]*)', iface['tag'])
                for (physnet, phys_iface) in self.physnets.items():
                    if iface['name'].startswith(phys_iface):
                        # will use physnet below
                        break
                else:
                    LOG.warning("Physical interface %s not registered in "
                                "current configuration", iface['name'])
                    break

                if_idx = iface['sw_if_idx']
                net_type = m.group(1)
                try:
                    seg_id = int(m.group(2))
                except ValueError:
                    seg_id = None

                if if_idx not in self.vpp.get_ifaces_in_bridge_domain(if_idx):
                    LOG.warning("Interface does not belong to "
                                "a bridge domain", iface['name'])
                    if net_type == 'vlan':
                        self.vpp.delete_vlan_subif(iface['sw_if_idx'])
                    # TODO(cfontaine): handle vxlan...
                    # elif net_type == 'vxlan':
                    elif net_type != 'flat':
                        LOG.warning('Unknown net_type: %s for interface',
                                    net_type, iface['name'])
                    break

                for sub_iface in vpp_interfaces:
                    if sub_iface['sw_if_idx'] == if_idx:
                        sup_iface_idx = sub_iface['sup_sw_if_idx']
                        break
                else:
                    sup_iface_idx = if_idx

                for sup_iface in vpp_interfaces:
                    if sup_iface['sw_if_idx'] == sup_iface_idx:
                        sup_iface_name = sup_iface['name']
                        break
                else:
                    sup_iface_name = iface['name']

                # Read physical networks configuration
                self.networks[(physnet, net_type, seg_id)] = {
                    'bridge_domain_id': if_idx,  # bd_id == if_idx
                    'if_upstream': sup_iface_name,
                    'if_upstream_idx': iface['sw_if_idx'],
                    'network_type': net_type,
                    'segmentation_id': seg_id,
                    'physnet': physnet,
                }
                LOG.info('New network found in vpp: %s',
                         str(self.networks[(physnet, net_type, seg_id)]))

            # Unrecognised tag, not created from this agent,
            # maybe created manually or by a feature
            else:
                LOG.debug('Port without matching tag: %s %s',
                          iface['name'],
                          iface['tag'])
                pass

    def delete_unknown_interfaces(self):
        """Unbind all interfaces unknown from etcd.

        Called AFTER the resync is done.
        Nova may have sent delete requests, which may not have
        been seen by the agent (agent down, or resync), so delete
        all interfaces with a valid uuid but unknown to the agent.
        """
        uuid_check = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
                                '-[0-9a-f]{4}-[0-9a-f]{12}')

        for iface in self.vpp.get_interfaces():
            if (uuid_check.match(iface['tag'])
               and (iface['tag'] not in self.interfaces)):
                if iface['name'].startswith('VirtualEthernet0/0/'):
                    self.vpp.delete_vhostuser(iface['sw_if_idx'])
                elif iface['name'].startswith('tap'):
                    self.vpp.delete_tap(iface['sw_if_idx'])

    def delete_empty_bridges(self):
        for (bd_id, ifaces) in self.vpp.get_ifaces_in_bridge_domains().items():
            if len(ifaces) == 0:
                self.vpp.delete_bridge_domain(bd_id)


######################################################################

LEADIN = '/networking-vpp'  # TODO(ijw): make configurable?


class EtcdListener(object):
    def __init__(self, host, etcd_client, vppf, physnets):
        self.host = host
        self.etcd_client = etcd_client
        self.vppf = vppf
        self.physnets = physnets
        self.etcd_helper = nwvpp_utils.EtcdHelper(self.etcd_client)
        # We need certain directories to exist
        self.mkdir(LEADIN + '/state/%s/ports' % self.host)
        self.mkdir(LEADIN + '/nodes/%s/ports' % self.host)

        # key: if index in VPP; value: (ID, prop-dict) tuple
        self.iface_state = {}

        self.vppf.vhost_ready_callback = self._vhost_ready

    def mkdir(self, path):
        try:
            self.etcd_client.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass

    def repop_interfaces(self):
        pass

    # The vppf bits

    def unbind(self, id):
        self.vppf.unbind_interface_on_host(id)

    def bind(self, id, binding_type, mac_address, physnet, network_type,
             segmentation_id):
        # args['binding_type'] in ('vhostuser', 'plugtap'):
        props = self.vppf.bind_interface_on_host(binding_type,
                                                 id,
                                                 mac_address,
                                                 physnet,
                                                 network_type,
                                                 segmentation_id)

        iface_idx = props['iface_idx']
        self.iface_state[iface_idx] = (id, props)
        if (binding_type != 'vhostuser'
           or self.vppf.vhostuser_linked_up(iface_idx)):
            # Handle the case were the interface has already been
            # notified as up, as we need both the up-notification
            # and bind information ito be ready before we tell Nova
            # For tap devices, assume the interface is up
            # TODO(cfontaine): can we check the real connection state ?
            self._mark_up(iface_idx)

        return props

    def _vhost_ready(self, sw_if_index):
        if sw_if_index in self.iface_state:
            # This index is linked up, and it's one of ours
            self._mark_up(sw_if_index)

    def _mark_up(self, sw_if_index):
        """Flag to Nova that an interface is connected.

        Nova watches a key's existence before sending out
        bind events.  We set the key, and use the value
        to store debugging information.
        """
        LOG.debug('marking index %s as ready', str(sw_if_index))
        (port, props) = self.iface_state[sw_if_index]
        self.etcd_client.write(self.state_key_space + '/%s' % port,
                               json.dumps(props))

    AGENT_HEARTBEAT = 60  # seconds

    def process_ops(self):
        # TODO(ijw): needs to remember its last tick on reboot, or
        # reconfigure from start (which means that VPP needs it
        # storing, so it's lost on reboot of VPP)
        physnets = self.physnets.keys()
        for f in physnets:
            self.etcd_client.write(LEADIN + '/state/%s/physnets/%s'
                                   % (self.host, f), 1)

        self.port_key_space = LEADIN + "/nodes/%s/ports" % self.host
        self.state_key_space = LEADIN + "/state/%s/ports" % self.host

        self.etcd_helper.clear_state(self.state_key_space)

        class PortWatcher(EtcdWatcher):

            def do_tick(self):
                # The key that indicates to people that we're alive
                # (not that they care)
                self.etcd_client.write(LEADIN + '/state/%s/alive' %
                                       self.data.host,
                                       1, ttl=3 * self.heartbeat)

            def resync_start(self):
                """Called at begining of resync."""
                # No interface binding is done here, we only fill
                # the cache
                self.data.vppf.read_vpp_state()
                pass

            def resync_end(self):
                """End of resync phase.

                Now interfaces are created correctly, we have to
                delete all interfaces that are not known from etcd.
                """
                self.data.vppf.delete_unknown_interfaces()
                self.data.vppf.delete_empty_bridges()
                pass

            def do_work(self, action, key, value):
                # Matches a port key, gets host and uuid
                m = re.match(self.data.port_key_space + '/([^/]+)$', key)

                if m:
                    port = m.group(1)

                    if action == 'delete':
                        # Removing key == desire to unbind
                        self.data.unbind(port)
                        try:
                            self.etcd_client.delete(
                                self.data.state_key_space + '/%s'
                                % port)
                        except etcd.EtcdKeyNotFound:
                            # Gone is fine; if we didn't delete it
                            # it's no problem
                            pass
                    else:
                        # Create or update == bind
                        data = json.loads(value)
                        self.data.bind(port,
                                       data['binding_type'],
                                       data['mac_address'],
                                       data['physnet'],
                                       data['network_type'],
                                       data['segmentation_id'])

                else:
                    LOG.warning('Unexpected key change in etcd port feedback, '
                                'key %s', key)

        PortWatcher(self.etcd_client, 'return_worker', self.port_key_space,
                    heartbeat=self.AGENT_HEARTBEAT, data=self).watch_forever()


class VPPRestart(object):
    def __init__(self):
        self.timeout = 10  # VPP connect timeout in seconds
        LOG.debug("Agent is restarting VPP")
        utils.execute(['service', 'vpp', 'restart'], run_as_root=True)

    def wait(self):
        time.sleep(self.timeout)  # TODO(najoy): check if vpp is actually up


def main():
    cfg.CONF(sys.argv[1:])
    logging.setup(cfg.CONF, 'vpp_agent')

    # If the user and/or group are specified in config file, we will use
    # them as configured; otherwise we try to use defaults depending on
    # distribution. Currently only supporting ubuntu and redhat.
    cfg.CONF.register_opts(config_opts.vpp_opts, "ml2_vpp")
    if cfg.CONF.ml2_vpp.enable_vpp_restart:
        LOG.debug('Restarting VPP..')
        VPPRestart().wait()

    if not cfg.CONF.ml2_vpp.physnets:
        LOG.error("Missing physnets config. Exiting...")
        sys.exit(1)

    physnet_list = cfg.CONF.ml2_vpp.physnets.replace(' ', '').split(',')
    physnets = {}
    for f in physnet_list:
        if f:
            try:
                (k, v) = f.split(':')
                physnets[k] = v
            except Exception:
                LOG.error("Could not parse physnet to interface mapping "
                          "check the format in the config file: "
                          "physnets = physnet1:<interface1>, "
                          "physnet2:<interface>"
                          )
                sys.exit(1)
    vppf = VPPForwarder(physnets,
                        vxlan_src_addr=cfg.CONF.ml2_vpp.vxlan_src_addr,
                        vxlan_bcast_addr=cfg.CONF.ml2_vpp.vxlan_bcast_addr,
                        vxlan_vrf=cfg.CONF.ml2_vpp.vxlan_vrf)

    LOG.debug("Using etcd host:%s port:%s user:%s password:***",
              cfg.CONF.ml2_vpp.etcd_host,
              cfg.CONF.ml2_vpp.etcd_port,
              cfg.CONF.ml2_vpp.etcd_user)

    host = nwvpp_utils.parse_host_config(cfg.CONF.ml2_vpp.etcd_host)

    etcd_client = etcd.Client(host=host,
                              port=cfg.CONF.ml2_vpp.etcd_port,
                              username=cfg.CONF.ml2_vpp.etcd_user,
                              password=cfg.CONF.ml2_vpp.etcd_pass,
                              allow_reconnect=True)

    ops = EtcdListener(cfg.CONF.host, etcd_client, vppf, physnets)

    ops.process_ops()

if __name__ == '__main__':
    main()
