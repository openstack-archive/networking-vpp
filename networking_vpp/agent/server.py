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

from abc import ABCMeta
from abc import abstractmethod
import etcd
import json
import os
import re
import six
import sys
import threading
import time
import vpp

from networking_vpp.agent import utils as nwvpp_utils
from networking_vpp import config_opts
from networking_vpp.etcdutils import EtcdWatcher
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from oslo_config import cfg
from oslo_log import log as logging
from stevedore import extension

# TODO(ijw): backward compatibility, wants removing in future
try:
    from neutron_lib import constants as n_const
except ImportError:
    from neutron.common import constants as n_const

LOG = logging.getLogger(__name__)


# config_opts is required to configure the options within it, but
# not referenced from here, so shut up tox:
assert config_opts

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
        # Used as a unique number for bridge IDs
        self.next_bridge_id = 5678

        self.networks = {}      # (physnet, type, ID): datastruct
        self.interfaces = {}    # uuid: if idx

    def get_vpp_ifidx(self, if_name):
        """Return VPP's interface index value for the network interface"""
        if self.vpp.get_interface(if_name):
            return self.vpp.get_interface(if_name).sw_if_index
        else:
            LOG.error("Error obtaining interface data from vpp "
                      "for interface:%s", if_name)
            return None

    def get_interface(self, physnet):
        return self.physnets.get(physnet, None)

    def new_bridge_domain(self):
        x = self.next_bridge_id
        self.vpp.create_bridge_domain(x)
        self.next_bridge_id += 1
        return x

    def network_on_host(self, physnet, net_type, seg_id=None):
        """Find or create a network of the type required"""
        if (physnet, net_type, seg_id) not in self.networks:
            self.create_network_on_host(physnet, net_type, seg_id)
        return self.networks.get((physnet, net_type, seg_id), None)

    def create_network_on_host(self, physnet, net_type, seg_id):
        intf = self.get_interface(physnet)
        if intf is None:
            LOG.error("Error: no physnet found")
            return None

        ifidx = self.get_vpp_ifidx(intf)

        # TODO(ijw): bridge domains have no distinguishing marks.
        # VPP needs to allow us to name or label them so that we
        # can find them when we restart.  If we add an interface
        # to two bridges that will likely not do as required

        if net_type == 'flat':
            if_upstream = ifidx

            LOG.debug('Adding upstream interface-idx:%s-%s to bridge '
                      'for flat networking' % (intf, if_upstream))

        elif net_type == 'vlan':
            self.vpp.ifup(ifidx)

            LOG.debug('Adding upstream VLAN interface %s.%s '
                      'to bridge for vlan networking' % (intf, seg_id))
            if not self.vpp.get_interface('%s.%s' % (intf, seg_id)):
                if_upstream = self.vpp.create_vlan_subif(ifidx,
                                                         seg_id)
            else:
                if_upstream = self.get_vpp_ifidx('%s.%s' % (intf, seg_id))
                self.vpp.set_vlan_remove(if_upstream)
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

        id = self.new_bridge_domain()

        self.vpp.add_to_bridge(id, if_upstream)
        self.networks[(physnet, net_type, seg_id)] = {
            'bridge_domain_id': id,
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
                iface = self.vpp.get_interface(net['if_upstream']
                                               + '.' + str(seg_id))
                self.vpp.delete_vlan_subif(iface.sw_if_index)

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
                LOG.debug('External tap device %s found!'
                          % device_name)
                LOG.debug('Bridging tap interface %s on %s'
                          % (device_name, bridge_name))
                if not bridge.owns_interface(device_name):
                    bridge.addif(device_name)
                else:
                    LOG.debug('Interface: %s is already added '
                              'to the bridge %s' %
                              (device_name, bridge_name))
                found = True
                break
            else:
                time.sleep(2)
                wait_time -= 2
        if not found:
            LOG.error('Failed waiting for external tap device:%s',
                      device_name)

    def create_interface_on_host(self, if_type, uuid, mac):
        if uuid in self.interfaces:
            LOG.debug('port %s repeat binding request - ignored', uuid)
        else:
            LOG.debug('binding port %s as type %s' %
                      (uuid, if_type))

            # TODO(ijw): naming not obviously consistent with
            # Neutron's naming
            name = uuid[0:11]
            bridge_name = 'br-' + name
            tap_name = 'tap' + name

            if if_type == 'maketap' or if_type == 'plugtap':
                if if_type == 'maketap':
                    iface_idx = self.vpp.create_tap(tap_name, mac)
                    props = {'name': tap_name}
                else:
                    int_tap_name = 'vpp' + name

                    props = {'bridge_name': bridge_name,
                             'ext_tap_name': tap_name,
                             'int_tap_name': int_tap_name}

                    LOG.debug('Creating tap interface %s with mac %s'
                              % (int_tap_name, mac))
                    iface_idx = self.vpp.create_tap(int_tap_name, mac)
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
            elif if_type == 'vhostuser':
                path = get_vhostuser_name(uuid)
                iface_idx = self.vpp.create_vhostuser(path, mac)
                props = {'path': path}
            else:
                raise UnsupportedInterfaceException(
                    'unsupported interface type')
            props['bind_type'] = if_type
            props['iface_idx'] = iface_idx
            props['mac'] = mac
            self.interfaces[uuid] = props
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
                  'bridge domain:%s'
                  % (iface_idx, net_br_idx))
        return props

    def unbind_interface_on_host(self, uuid):
        if uuid not in self.interfaces:
            LOG.debug('unknown port %s unbinding request - ignored'
                      % uuid)
        else:
            props = self.interfaces[uuid]
            iface_idx = props['iface_idx']

            LOG.debug('unbinding port %s, recorded as type %s'
                      % (uuid, props['bind_type']))

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


######################################################################


@six.add_metaclass(ABCMeta)
class AgentFeature(object):
    """Abstract class to handle etcd notifications.

    For each 'feature', the pattern is the following:
    - watch new data under 'LEADIN/nodes/<host>/<feature>/<unique_id>'
    For each event, the method 'set' or 'delete' is called.
    - the agent returns data under 'LEADIN/state/<host>/<feature>/<unique_id>'
    """

    path = ''

    """ For system wide features, watch under 'LEADING/<feature>/<unique_id>'
    """
    is_system_wide = False

    def __init__(self, host, etcd_client, vppf):
        self._host = host
        self._etcd_client = etcd_client
        self._etcd_helper = nwvpp_utils.EtcdHelper(self._etcd_client)
        self._vppf = vppf
        if self.is_system_wide:
            self._node_key_space = LEADIN + '/%s' % (self.path)
        else:
            self._node_key_space = LEADIN + '/nodes/%s/%s' % (host, self.path)
        self._state_key_space = LEADIN + '/state/%s/%s' % (host, self.path)
        pass

    @abstractmethod
    def set(self, key, value):
        """feature for host is created or updated.

        eg: This is called when the server wants the agent
        to bind a port.
        this agent will return the state under the key
        'self._state_key_space'
        """
        pass

    @abstractmethod
    def delete(self, key, value):
        """feature for host has to be deleted.

        eg: This is called when the server wants the agent
        to unbind a port.
        this agent will delete the state under the key
        'self._state_key_space'
        """
        pass

    def resync(self):
        """Resync state on startup or etcd resync

        On agent startup or when the sync with the etcd db
        is lost, the agent has to clean its internal state
        as the whole state will be read.
        """
        pass

    def tick(self):
        """Periodic method called at each watch timeout.

        Usefull to advertise current status.
        """
        pass


class PortAgentFeature(AgentFeature):
    """Port Bind/Unbind management.

    For each port bind/unbind, we watch the port info
    under 'LEADIN/nodes/<host>/ports/<port_id>'.
    After the connection of the port, we write the info
    under 'LEADIN/state/<host>/ports/<port_id>' to notify
    neutron server.
    """

    path = 'ports'

    def set(self, key, value):
        # Create or update == bind
        port = key
        data = json.loads(value)
        props = self._vppf.bind_interface_on_host(data['binding_type'],
                                                  port,
                                                  data['mac_address'],
                                                  data['physnet'],
                                                  data['network_type'],
                                                  data['segmentation_id'])
        self._etcd_client.write(self._state_key_space +
                                '/%s' % port,
                                json.dumps(props))

    def delete(self, key, value):
        # Removing key == desire to unbind
        port = key
        self._vppf.unbind_interface_on_host(port)
        try:
            self._etcd_client.delete(self._state_key_space +
                                     '/%s' % port)
        except etcd.EtcdKeyNotFound:
            # Gone is fine, if we didn't delete it
            # it's no problem
            pass

    def resync(self):
        self._etcd_helper.clear_state(self._state_key_space)
        # TODO(ijw): Need to do something here to prompt
        # appropriate unbind/rebind behaviour
        pass


class PhysnetsAgentFeature(AgentFeature):

    path = 'physnets'

    def set(self, key, value):
        pass

    def delete(self, key, value):
        pass

    def resync(self):
        # On resync, (also at startup), advertise on
        # which physnets we have a connection.
        for physnet in self._vppf.physnets.keys():
            self._etcd_client.write(self._state_key_space +
                                    '/' + physnet, 1)


LEADIN = '/networking-vpp'  # TODO(ijw): make configurable?


class EtcdListener(object):
    def __init__(self, host, etcd_client, vppf):
        self.features = {}
        self.host = host
        self.etcd_client = etcd_client
        self.vppf = vppf
        self.etcd_helper = nwvpp_utils.EtcdHelper(self.etcd_client)

    def mkdir(self, path):
        try:
            self.etcd_client.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass

    def register_feature(self, feature):
        if feature.path in self.features.keys():
            raise Exception('Feature "%s" already registered' % feature.path)
        self.features[feature.path] = feature
        # We need directories to exist for each registered feature
        self.mkdir(LEADIN + '/state/%s/%s' % (self.host, feature.path))
        if feature.is_system_wide:
            self.mkdir(LEADIN + '/%s' % (feature.path))
        else:
            self.mkdir(LEADIN + '/nodes/%s/%s' % (self.host, feature.path))
        LOG.info('Added Feature: %s' % feature.path)

    AGENT_HEARTBEAT = 60  # seconds

    def process_ops(self):
        # TODO(ijw): needs to remember its last tick on reboot, or
        # reconfigure from start (which means that VPP needs it
        # storing, so it's lost on reboot of VPP)
        self.agent_key_space = LEADIN + "/nodes/%s" % self.host

        class AgentWatcher(EtcdWatcher):

            def do_tick(self):
                self.etcd_client.write(LEADIN + '/state/%s/alive'
                                       % self.data.host,
                                       1, ttl=3 * self.heartbeat)
                for feature in self.data.features.values():
                    feature.tick()

            def resync(self):
                for feature in self.data.features.values():
                    feature.resync()

            def do_work(self, action, key, value):
                m = re.match(LEADIN + '/nodes/' + self.data.host +
                             '/([^/]+)/([^/]+)$', key)
                if m:
                    feature = m.group(1)
                    key = m.group(2)
                    if action is None:
                        # occurs when resyncing
                        action = 'set'
                    feature_instance = self.data.features[feature]
                    getattr(feature_instance, action)(key, value)

                else:
                    LOG.warning('Unexpected key change in etcd port feedback, '
                                'key %s', key)

        AgentWatcher(self.etcd_client, 'return_worker', self.agent_key_space,
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

    LOG.debug("Using etcd host:%s port:%s user:%s password:***" %
              (cfg.CONF.ml2_vpp.etcd_host,
               cfg.CONF.ml2_vpp.etcd_port,
               cfg.CONF.ml2_vpp.etcd_user,))

    etcd_client = etcd.Client(host=cfg.CONF.ml2_vpp.etcd_host,
                              port=cfg.CONF.ml2_vpp.etcd_port,
                              username=cfg.CONF.ml2_vpp.etcd_user,
                              password=cfg.CONF.ml2_vpp.etcd_pass,
                              allow_reconnect=True)

    ops = EtcdListener(cfg.CONF.host, etcd_client, vppf)

    mgr = extension.ExtensionManager(namespace='networking_vpp.agent.features',
                                     invoke_on_load=True,
                                     invoke_args=(cfg.CONF.host,
                                                  etcd_client,
                                                  vppf))
    agent_features = [ext.obj for ext in mgr.extensions]

    for feature in agent_features:
        ops.register_feature(feature)

    ops.process_ops()


if __name__ == '__main__':
    main()
