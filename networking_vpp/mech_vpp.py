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

import abc
from abc import abstractmethod
from collections import namedtuple
import etcd
import eventlet
import eventlet.event
import json
from oslo_config import cfg
from oslo_log import log as logging
import re
import six
import time
import traceback

import backward_compatibility as bc_attr

from networking_vpp.agent import utils as nwvpp_utils
from networking_vpp import config_opts
from networking_vpp.db import db
from networking_vpp.etcdutils import EtcdWatcher
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron import context as n_context
from neutron.db import api as neutron_db_api
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api


# TODO(ijw): backward compatibility, wants removing in future
try:
    from neutron_lib import constants as n_const
except ImportError:
    from neutron.common import constants as n_const

# TODO(cfontaine): backward compatibility, wants removing in future
try:
    from neutron_lib.plugins import directory
except ImportError:
    from neutron import manager
    directory = manager.NeutronManager

eventlet.monkey_patch()

LOG = logging.getLogger(__name__)


class VPPMechanismDriver(api.MechanismDriver):
    supported_vnic_types = [portbindings.VNIC_NORMAL]
    allowed_network_types = [p_constants.TYPE_FLAT,
                             p_constants.TYPE_VLAN,
                             p_constants.TYPE_VXLAN]
    MECH_NAME = 'vpp'

    vif_details = {}

    def initialize(self):
        cfg.CONF.register_opts(config_opts.vpp_opts, "ml2_vpp")
        self.communicator = EtcdAgentCommunicator()

    def get_vif_type(self, port_context):
        """Determine the type of the vif to be bound from port context"""

        # Default vif type
        vif_type = 'vhostuser'

        # We have to explicitly avoid binding agent ports - DHCP,
        # L3 etc. - as vhostuser. The interface code below takes
        # care of those.

        owner = port_context.current['device_owner']
        for f in bc_attr.DEVICE_OWNER_PREFIXES:
            if owner.startswith(f):
                vif_type = 'plugtap'
        LOG.debug("ML2_VPP: vif_type to be bound is: %s", vif_type)
        return vif_type

    def bind_port(self, port_context):
        """Attempt to bind a port.

        :param port_context: PortContext instance describing the port

        This method is called outside any transaction to attempt to
        establish a port binding using this mechanism driver. Bindings
        may be created at each of multiple levels of a hierarchical
        network, and are established from the top level downward. At
        each level, the mechanism driver determines whether it can
        bind to any of the network segments in the
        port_context.segments_to_bind property, based on the value of the
        port_context.host property, any relevant port or network
        attributes, and its own knowledge of the network topology. At
        the top level, port_context.segments_to_bind contains the static
        segments of the port's network. At each lower level of
        binding, it contains static or dynamic segments supplied by
        the driver that bound at the level above. If the driver is
        able to complete the binding of the port to any segment in
        port_context.segments_to_bind, it must call port_context.set_binding
        with the binding details. If it can partially bind the port,
        it must call port_context.continue_binding with the network
        segments to be used to bind at the next lower level.

        If the binding results are committed after bind_port returns,
        they will be seen by all mechanism drivers as
        update_port_precommit and update_port_postcommit calls. But if
        some other thread or process concurrently binds or updates the
        port, these binding results will not be committed, and
        update_port_precommit and update_port_postcommit will not be
        called on the mechanism drivers with these results. Because
        binding results can be discarded rather than committed,
        drivers should avoid making persistent state changes in
        bind_port, or else must ensure that such state changes are
        eventually cleaned up.

        Implementing this method explicitly declares the mechanism
        driver as having the intention to bind ports. This is inspected
        by the QoS service to identify the available QoS rules you
        can use with ports.
        """
        LOG.debug("ML2_VPP: Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': port_context.current['id'],
                   'network': port_context.network.current['id']})
        vnic_type = port_context.current.get(portbindings.VNIC_TYPE,
                                             portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("ML2_VPP: Refusing to bind due to unsupported "
                      "vnic_type: %s",
                      vnic_type)
            return

        for segment in port_context.segments_to_bind:
            if self.check_segment(segment, port_context.host):
                vif_details = dict(self.vif_details)
                # TODO(ijw) should be in a library that the agent uses
                vif_type = self.get_vif_type(port_context)
                if vif_type == 'vhostuser':
                    vif_details['vhostuser_socket'] = \
                        '/tmp/%s' % port_context.current['id']
                    vif_details['vhostuser_mode'] = 'server'
                LOG.debug('ML2_VPP: Setting details: %s', vif_details)
                port_context.set_binding(segment[api.ID],
                                         vif_type,
                                         vif_details)
                LOG.debug("ML2_VPP: Bound using segment: %s", segment)
                return

    def check_segment(self, segment, host):
        """Check if segment can be bound.

        :param segment: segment dictionary describing segment to bind
        :param host: host on which the segment must be bound to a port
        :returns: True iff segment can be bound for host

        """

        # TODO(ijw): naive - doesn't check host, or configured
        # physnets on the host.  Should work out if the binding
        # can't be achieved before accepting it

        network_type = segment[api.NETWORK_TYPE]
        if network_type not in self.allowed_network_types:
            LOG.debug(
                'ML2_VPP: Network %(network_id)s is %(network_type)s, '
                'but this driver only supports types '
                '%(allowed_network_types)s. '
                'The type must be supported  if binding is to succeed.',
                {'network_id': segment['id'],
                 'network_type': network_type,
                 'allowed_network_types':
                 ', '.join(self.allowed_network_types)}
            )
            return False

        if network_type in [p_constants.TYPE_FLAT, p_constants.TYPE_VLAN]:
            physnet = segment[api.PHYSICAL_NETWORK]
            if not self.physnet_known(host, physnet):
                LOG.debug(
                    'ML2_VPP: Network %(network_id)s is on physical '
                    'network %(physnet)s, but the physical network '
                    'is not one the host %(host)s has attached.',
                    {'network_id': segment['id'],
                     'physnet': physnet,
                     'host': host}
                )
                return False

        return True

    def physnet_known(self, host, physnet):
        return (host, physnet) in self.communicator.find_physnets()

    def check_vlan_transparency(self, port_context):
        """Check if the network supports vlan transparency.

        :param port_context: NetworkContext instance describing the network.

        In general we do not support VLAN transparency (yet).
        """
        return False

    def update_port_precommit(self, port_context):
        """Work to do, during DB commit, when updating a port

        If we are partially responsible for binding this port, we will
        have to tell our agents they have work to do.  This is an
        operation within a distributed system and can therefore take
        time to complete, or potentially even fail.  Instead, we log
        the requirement to a journal.
        """
        # TODO(ijw): optimisation: the update port may leave the
        # binding state the same as before if someone updated
        # something other than the binding on the port, but this
        # way we always send it out and it's the far end's job to
        # ignore it.  Doing less work is nevertheless good, so we
        # should in future avoid the send.

        if port_context.binding_levels is not None:
            current_bind = port_context.binding_levels[-1]
            if port_context.original_binding_levels is None:
                prev_bind = None
            else:
                prev_bind = port_context.original_binding_levels[-1]

            binding_type = self.get_vif_type(port_context)

            if (current_bind is not None and
               current_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                # then send the bind out (may equally be an update on a bound
                # port)
                self.communicator.bind(port_context._plugin_context.session,
                                       port_context.current,
                                       current_bind[api.BOUND_SEGMENT],
                                       port_context.host,
                                       binding_type)
            elif (prev_bind is not None and
                  prev_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                # If we were the last binder of this port but are no longer
                self.communicator.unbind(port_context._plugin_context.session,
                                         port_context.current,
                                         port_context.original_host)

    def update_port_postcommit(self, port_context):
        """Work to do, post-DB commit, when updating a port

        After accepting an update_port, determine if we logged any
        work to do on the networking devices, and - if so - kick the
        update thread that tells our minions.

        """
        # TODO(ijw): optimisation: the update port may leave the
        # binding state the same as before if someone updated
        # something other than the binding on the port, but this
        # way we always send it out and it's the far end's job to
        # ignore it.  Doing less work is nevertheless good, so we
        # should in future avoid the send.

        if port_context.binding_levels is not None:
            current_bind = port_context.binding_levels[-1]
            if port_context.original_binding_levels is None:
                prev_bind = None
            else:
                prev_bind = port_context.original_binding_levels[-1]

            if (current_bind is not None and
               current_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                self.ensure_secgroups_in_etcd(port_context)
                self.communicator.kick()
            elif (prev_bind is not None and
                  prev_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                self.ensure_secgroups_in_etcd(port_context)
                self.communicator.kick()

    def delete_port_precommit(self, port_context):
        port = port_context.current
        host = port_context.host
        LOG.debug('ML2_VPP: delete_port_postcommit, port is %s', str(port))
        self.communicator.unbind(port_context._plugin_context.session,
                                 port, host)

    def delete_port_postcommit(self, port_context):
        self.communicator.kick()

    def ensure_secgroups_in_etcd(self, port_context):
        """Ensure secgroup key-value is present in etcd if enabled"""
        if self.communicator.secgroup_enabled:
            sgids = port_context.current.get('security_groups', [])
            for sgid in sgids:
                if not self.communicator.secgroup_key_present(sgid):
                    LOG.debug("ML2_VPP: Update port postcommit "
                              "writing missing secgroup %s to etcd" % sgid)
                    self.communicator.send_sg_updates(
                        [sgid],
                        port_context._plugin_context
                        )


@six.add_metaclass(abc.ABCMeta)
class AgentCommunicator(object):

    def __init__(self):
        self.recursive = False

    @abstractmethod
    def bind(self, port, segment, host, binding_type):
        pass

    @abstractmethod
    def unbind(self, port, host):
        pass

    def notify_bound(self, port_id, host):
        """Tell things that the port is truly bound.

        You want to call this when you're certain that the VPP
        on the far end has definitely bound the port, and has
        dropped a vhost-user socket where it can be found.

        You want to do this then specifically because libvirt
        will hang, because qemu ignores its monitor port,
        when qemu is waiting for a partner to connect with on
        its vhost-user interfaces.  It can't start the VM - that
        requires information from its partner it can't guess at -
        but it shouldn't hang the monitor - nevertheless...

        In the case your comms protocol is sucky, call it at
        the end of a bind() and everything will probably be
        fine.  Probably.
        """

        context = n_context.get_admin_context()

        plugin = directory.get_plugin()
        # Bodge TODO(ijw)
        if self.recursive:
            # This happens right now because when we update the port
            # status, we update the port and the update notification
            # comes through to here.
            # TODO(ijw) wants a more permanent fix, because this only
            # happens due to the threading model.  We should be
            # spotting relevant changes in postcommit.
            LOG.warning('ML2_VPP: recursion check hit on activating port')
        else:
            self.recursive = True
            plugin.update_port_status(context, port_id,
                                      n_const.PORT_STATUS_ACTIVE,
                                      host=host)
            self.recursive = False


# If no-one from Neutron talks to us in this long, get paranoid and check the
# database for work.  We might have missed the kick (or another
# process may have added work and then died before processing it).
PARANOIA_TIME = 50              # TODO(ijw): make configurable?
# Our prefix for etcd keys, in case others are using etcd.
LEADIN = '/networking-vpp'      # TODO(ijw): make configurable?
# Model for representing a security group
SecurityGroup = namedtuple(
    'SecurityGroup', ['id', 'ingress_rules', 'egress_rules']
    )
# Model for a VPP security group rule
SecurityGroupRule = namedtuple(
    'SecurityGroupRule', ['is_ipv6', 'remote_ip_addr',
                          'ip_prefix_len', 'protocol',
                          'port_min', 'port_max']
    )


class EtcdAgentCommunicator(AgentCommunicator):
    """Comms unit for etcd

    This will talk to etcd and tell it what is going on
    with the Neutron database.  etcd can be run as a
    cluster and so shouldn't die, but can be unreachable,
    so this class's job is to ensure that all updates are
    forwarded to etcd in order even when things are not
    quite going as planned.

    In etcd, the layout is:
    LEADIN/nodes - subdirs are compute nodes
    LEADIN/nodes/X/ports - entries are JSON-ness containing
    all information on each bound port on the compute node.
    (Unbound ports are homeless, so the act of unbinding is
    the deletion of this entry.)
    LEADIN/state/nodes/X - return state of the VPP
    LEADIN/state/nodes/X/alive - heartbeat back
    LEADIN/state/nodes/X/ports - port information.
    LEADIN/state/nodes/X/physnets - physnets on node
    Specifically a key here (regardless of value) indicates
    the port has been bound and is receiving traffic.
    """

    def __init__(self):
        super(EtcdAgentCommunicator, self).__init__()
        LOG.debug("Using etcd host:%s port:%s user:%s password:***" %
                  (cfg.CONF.ml2_vpp.etcd_host,
                   cfg.CONF.ml2_vpp.etcd_port,
                   cfg.CONF.ml2_vpp.etcd_user,))

        host = nwvpp_utils.parse_host_config(cfg.CONF.ml2_vpp.etcd_host)
        self.etcd_client = etcd.Client(host=host,
                                       port=cfg.CONF.ml2_vpp.etcd_port,
                                       username=cfg.CONF.ml2_vpp.etcd_user,
                                       password=cfg.CONF.ml2_vpp.etcd_pass,
                                       allow_reconnect=True)
        # We need certain directories to exist
        self.state_key_space = LEADIN + '/state'
        self.port_key_space = LEADIN + '/nodes'
        self.secgroup_key_space = LEADIN + '/secgroups'
        self.do_etcd_mkdir(self.state_key_space)
        self.do_etcd_mkdir(self.port_key_space)
        self.do_etcd_mkdir(self.secgroup_key_space)
        self.secgroup_enabled = cfg.CONF.SECURITYGROUP.enable_security_group
        if self.secgroup_enabled:
            self.register_secgroup_event_handler()

        # TODO(ijw): .../state/<host> lists all known hosts, and they
        # heartbeat when they're functioning

        self.db_q_ev = eventlet.event.Event()
        try:
            # Liberty, Mitaka
            ev = events.AFTER_INIT
        except Exception:
            # Newton and on
            ev = events.AFTER_CREATE

        registry.subscribe(self.start_threads, resources.PROCESS, ev)

    def start_threads(self, resource, event, trigger):
        LOG.debug('Starting background threads for Neutron worker')
        self.return_thread = eventlet.spawn(self._return_worker)
        self.forward_thread = eventlet.spawn(self._forward_worker)

    def find_physnets(self):
        physical_networks = set()
        for rv in self.etcd_client.read(LEADIN, recursive=True).children:
            # Find all known physnets
            m = re.match(self.state_key_space + '/([^/]+)/physnets/([^/]+)$',
                         rv.key)
            if m:
                host = m.group(1)
                net = m.group(2)
                physical_networks.add((host, net))

        return physical_networks

    def register_secgroup_event_handler(self):
        """Subscribe a handler to process secgroup change notifications"""
        # A mapping for looking up the security_group_id of the
        # deleted_rule. This is needed as neutron does not send the
        # security_group_id of the rule in the callback notification
        LOG.info("ML2_VPP: Security groups feature is enabled")
        self.deleted_rules = {}
        registry.subscribe(self.process_secgroup_events,
                           resources.SECURITY_GROUP,
                           events.AFTER_DELETE)
        registry.subscribe(self.process_secgroup_events,
                           resources.SECURITY_GROUP_RULE,
                           events.AFTER_CREATE)
        registry.subscribe(self.process_secgroup_events,
                           resources.SECURITY_GROUP_RULE,
                           events.BEFORE_DELETE)
        registry.subscribe(self.process_secgroup_events,
                           resources.SECURITY_GROUP_RULE,
                           events.AFTER_DELETE)
        LOG.info("ML2_VPP: subscribed to receive security group delete "
                 "and rule create/delete notifications")

    def process_secgroup_events(self, resource, event, trigger, **kwargs):
        """Callback for handling security group change events"""
        LOG.debug("ML2_VPP: Received event %s notification for resource"
                  " %s with kwargs %s" % (event, resource, kwargs))
        context = kwargs['context']
        if resource == resources.SECURITY_GROUP:
            self.delete_secgroup_from_etcd(kwargs['security_group_id'])
        elif resource == resources.SECURITY_GROUP_RULE:
            if event == events.BEFORE_DELETE:
                rule_id = kwargs['security_group_rule_id']
                rule = self.get_secgroup_rule(rule_id, context)
                LOG.debug("ML2_VPP: Fetched rule %s for rule_id %s" %
                          (rule, rule_id))
                security_group_id = rule['security_group_id']
                self.deleted_rules[rule_id] = security_group_id
            elif event == events.AFTER_DELETE:
                rule_id = kwargs['security_group_rule_id']
                security_group_id = self.deleted_rules.get(rule_id)
                LOG.debug("ML2_VPP: Fetched secgroup_id %s for "
                          "rule-id %s" % (security_group_id, rule_id))
                if not security_group_id:
                    LOG.error("ML2_VPP: Could not lookup a security group "
                              "for rule_id %s" % rule_id)
                else:
                    del self.deleted_rules[rule_id]
            elif event == events.AFTER_CREATE:
                rule = kwargs['security_group_rule']
                security_group_id = rule['security_group_id']
            if security_group_id:
                self.send_sg_updates([security_group_id], context)

    def send_sg_updates(self, sgids, context):
        """Called when security group rules are updated

        Arguments:
        sgids - A list of one or more security_group_ids
        context - The plugin context i.e. neutron.context.Context object

        1. Read security group rules from neutron DB
        2. Build security group objects from their rules
        3. Write secgroup to the secgroup_key_space in etcd
        """
        LOG.debug("ML2_VPP: etcd_communicator sending security group "
                  "updates for groups %s to etcd" % sgids)
        db = manager.NeutronManager.get_plugin()
        with context.session.begin(subtransactions=True):
            rules = db.get_security_group_rules(
                context, filters={'security_group_id': sgids}
                )
            LOG.debug("ML2_VPP: SecGroup rules from neutron DB: %s" % rules)
            # Build a generator of security group model objects from DB rules
            secgroups = (
                self.get_secgroup_from_rules(sgid, rules) for sgid in sgids
                )
            # Write security group data to etcd
            for secgroup in secgroups:
                self.write_secgroup_to_etcd(secgroup)

    def get_secgroup_rule(self, rule_id, context):
        """Fetch and return a security group rule from Neutron DB"""
        LOG.debug("ML2_VPP: fetching security group rule: %s" % rule_id)
        db = manager.NeutronManager.get_plugin()
        with context.session.begin(subtransactions=True):
            return db.get_security_group_rule(context, rule_id)

    def get_secgroup_from_rules(self, sgid, rules):
        """Build and return a security group namedtuple object.

        Arguments:
        sgid - ID of the security group
        rules - A list of security group rules

        1. Filter rules using the input param: sgid to ensure that rules
        belong to that group
        2. Split rules based on direction.
        3. Construct and return the SecurityGroup namedtuple.
        """
        # A generator object of security group rules for sgid
        sg_rules = (r for r in rules if r['security_group_id'] == sgid)
        # A list of ingress and egress namedtuple rule objects
        ingress_rules = []
        egress_rules = []
        for r in sg_rules:
            if r['direction'] == 'ingress':
                ingress_rules.append(self._neutron_rule_to_vpp_acl(r))
            else:
                egress_rules.append(self._neutron_rule_to_vpp_acl(r))
        return SecurityGroup(sgid, ingress_rules, egress_rules)

    def _neutron_rule_to_vpp_acl(self, rule):
        """Convert a neutron rule to vpp_acl rule.

        Arguments:
        1. rule -- represents a neutron rule

        - Convert the neutron rule to a vpp_acl rule model
        - Return the SecurityGroupRule namedtuple.
        """
        LOG.debug("ML2_VPP:Converting neutron rule %s" % rule)
        is_ipv6 = 0 if rule['ethertype'] == 'IPv4' else 1
        # Neutron uses None to represent any protocol
        # Use 0 to represent any protocol
        if rule['protocol'] is None:
            protocol = 0
        # VPP rules require IANA protocol numbers
        elif rule['protocol'] in ['tcp', 'udp', 'icmp', 'icmpv6']:
            protocol = {'tcp': 6,
                        'udp': 17,
                        'icmp': 1,
                        'icmpv6': 58}[rule['protocol']]
        else:
            protocol = rule['protocol']
        # Neutron represents any ip address by setting one
        # or both of the of the below fields to None
        # VPP uses all zeros to represent any Ipv4/IpV6 address
        # TODO(najoy) handle remote_group_id when remote_ip_prefix is None
        if (rule['remote_ip_prefix'] is None
                or rule['remote_group_id'] is None):
            remote_ip_addr = '0.0.0.0' if not is_ipv6 else '0:0:0:0:0:0:0:0'
            ip_prefix_len = 0
        else:
            remote_ip_addr, ip_prefix_len = rule['remote_ip_prefix'
                                                 ].split('/')
        # TODO(najoy): Add support for remote_group_id in sec-group-rules
        if rule['remote_group_id']:
            LOG.warning("ML2_VPP: A remote-group-id value is specified in "
                        "rule %s. Setting a remote_group_id in rules is "
                        "not supported" % rule)
        # Neutron uses -1 or None to represent all ports
        # VPP uses 0-65535 for all tcp/udp ports, Use -1 to represent all
        # ranges for ICMP types and codes
        if rule['port_range_min'] == -1 or rule['port_range_min'] is None:
            # Valid TCP/UDP port ranges
            if protocol in [6, 17]:
                port_min, port_max = (0, 65535)
            # A Value of -1 represents all ICMP/ICMPv6 types & code ranges
            elif protocol in [1, 58]:
                port_min, port_max = (-1, -1)
            # Ignore port_min and port_max fields
            else:
                port_min, port_max = (0, 0)
        else:
            port_min, port_max = (rule['port_range_min'],
                                  rule['port_range_max'])
        sg_rule = SecurityGroupRule(is_ipv6, remote_ip_addr, ip_prefix_len,
                                    protocol, port_min, port_max)
        LOG.debug("ML2_VPP: Converted rule: is_ipv6:%s, remote_ip_addr:%s,"
                  " ip_prefix_len:%s, protocol:%s, port_min:%s,"
                  " port_max:%s" %
                  (sg_rule.is_ipv6, sg_rule.remote_ip_addr,
                   sg_rule.ip_prefix_len, sg_rule.protocol,
                   sg_rule.port_min, sg_rule.port_max))
        return sg_rule

    def write_secgroup_to_etcd(self, secgroup):
        """Writes a secgroup to the etcd secgroup space

        Arguments:
        secgroup -- Named tuple representing a SecurityGroup
        """
        secgroup_path = self._secgroup_path(secgroup.id)
        # sg is a dict of of ingress and egress rule lists
        sg = {}
        ingress_rules = []
        egress_rules = []
        for ingress_rule in secgroup.ingress_rules:
            ingress_rules.append(ingress_rule._asdict())
        for egress_rule in secgroup.egress_rules:
            egress_rules.append(egress_rule._asdict())
        sg['ingress_rules'] = ingress_rules
        sg['egress_rules'] = egress_rules
        LOG.debug('ML2_VPP: Writing secgroup key-val: %s-%s to etcd' %
                  (secgroup_path, sg))
        self.etcd_client.write(secgroup_path, json.dumps(sg))

    def delete_secgroup_from_etcd(self, secgroup_id):
        """Deletes the secgroup key from etcd

        Arguments:
        secgroup_id -- The id of the security group that we want to delete
        """
        try:
            LOG.info("ML2_VPP: Deleting secgroup %s from etcd" %
                     secgroup_id)
            secgroup_path = self._secgroup_path(secgroup_id)
            self.etcd_client.delete(secgroup_path)
        except etcd.EtcdKeyNotFound:
            # Just log a message if the key is not found
            LOG.debug("ML2_VPP: secgroup key %s which we were attempting"
                      " to delete has disappeared" % secgroup_path)

    def _secgroup_path(self, secgroup_id):
        return self.secgroup_key_space + "/" + secgroup_id

    def secgroup_key_present(self, secgroup_id):
        """Return True if the key is present in etcd else False."""
        try:
            if self.etcd_client.read(self._secgroup_path(secgroup_id)):
                return True
        except etcd.EtcdKeyNotFound:
            return False

    def _port_path(self, host, port):
        return self.port_key_space + "/" + host + "/ports/" + port['id']

    ######################################################################
    # These functions use a DB journal to log messages before
    # they're put into etcd, as that can take time and may not always
    # succeed (so is a bad candidate for calling within or after a
    # transaction).

    kick_count = 0

    def kick(self):
        if not self.db_q_ev.ready():
            self.kick_count = self.kick_count + 1
            try:
                self.db_q_ev.send(self.kick_count)
            except AssertionError:
                # We send even on triggered events (which is fine: it's a
                # wakeup signal and harmless to send repeatedly), but
                # we need to ignore the error
                pass

    def bind(self, session, port, segment, host, binding_type):
        # NB segmentation_id is not optional in the wireline protocol,
        # we just pass 0 for unsegmented network types
        LOG.debug("ML2_VPP: Received bind request for port:%s"
                  % port)
        data = {
            'mac_address': port['mac_address'],
            'mtu': 1500,  # not this, but what?: port['mtu'],
            'physnet': segment[api.PHYSICAL_NETWORK],
            'network_type': segment[api.NETWORK_TYPE],
            'segmentation_id': segment.get(api.SEGMENTATION_ID, 0),
            'binding_type': binding_type,
            'security_groups': port['security_groups'],
            'allowed_address_pairs': port['allowed_address_pairs'],
            'fixed_ips': port['fixed_ips']
        }
        LOG.debug("ML2_VPP: Queueing bind request for port:%s, "
                  "segment:%s, host:%s, type:%s",
                  port, data['segmentation_id'],
                  host, data['binding_type'])

        db.journal_write(session, self._port_path(host, port), data)
        self.kick()

    def unbind(self, session, port, host):
        db.journal_write(session, self._port_path(host, port), None)
        self.kick()

    ######################################################################
    # The post-journal part of the work that clears out the table and
    # updates etcd.

    def do_etcd_update(self, k, v):
        try:
            # not needed? - do_etcd_mkdir('/'.join(k.split('/')[:-1]))
            if v is None:
                LOG.debug('deleting key %s', k)
                try:
                    self.etcd_client.delete(k)
                except etcd.EtcdKeyNotFound:
                    # The key may have already been deleted
                    # no problem here
                    pass
            else:
                LOG.debug('writing key %s', k)
                self.etcd_client.write(k, json.dumps(v))
            return True
        except Exception:       # TODO(ijw) select your exceptions
            return False

    def do_etcd_mkdir(self, path):
        try:
            self.etcd_client.write(path, None, dir=True)
        except etcd.EtcdNotFile:
            # Thrown when the directory already exists, which is fine
            pass

    def _forward_worker(self):
        LOG.debug('forward worker begun')

        session = neutron_db_api.get_session()
        while True:
            try:
                def work(k, v):
                    LOG.debug('forward worker updating etcd key %s', k)
                    if self.do_etcd_update(k, v):
                        return True
                    else:
                        # something went bad; breathe, in case we end
                        # up in a tight loop
                        time.sleep(1)
                        return False

                LOG.debug('forward worker reading journal')
                while db.journal_read(session, work):
                    pass
                LOG.debug('forward worker has emptied journal')

                # work queue is now empty.
                LOG.debug("ML2_VPP(%s): worker thread pausing"
                          % self.__class__.__name__)
                # Wait to be kicked, or (in case of emergency) run every
                # few seconds in case another thread or process dumped
                # work and failed to process it
                try:
                    with eventlet.Timeout(PARANOIA_TIME):
                        # Wait for kick
                        dummy = self.db_q_ev.wait()
                        # Clear the event - we will now process till
                        # we've run out of things in the backlog
                        # so any trigger lost in this gap is harmless
                        self.db_q_ev.reset()
                        LOG.debug("ML2_VPP(%s): worker thread kicked: %s"
                                  % (self.__class__.__name__, str(dummy)))
                except eventlet.Timeout:
                    LOG.debug("ML2_VPP(%s): worker thread suspicious of "
                              "a long pause"
                              % self.__class__.__name__)
                    pass
                LOG.debug("ML2_VPP(%s): worker thread active"
                          % self.__class__.__name__)
            except Exception as e:
                # TODO(ijw): log exception properly
                LOG.error("problems in forward worker: %s", e)
                LOG.error(traceback.format_exc())
                # never quit
                pass

    ######################################################################

    def _return_worker(self):
        """The thread that manages data returned from agents via etcd."""

        # TODO(ijw): this should begin by syncing state, particularly
        # of agents but also of any notifications for which we missed
        # the watch event.

        # TODO(ijw): agents
        # TODO(ijw): notifications

        class ReturnWatcher(EtcdWatcher):

            def resync(self):
                # Ports may have been bound.  do_work will send an
                # additional 'bound' notification for every port,
                # which is harmless

                # Agent deaths in this time will not be logged, so
                # make this clear
                LOG.info('Sync lost, resetting agent liveness')

            def do_work(self, action, key, value):
                # Matches a port key, gets host and uuid
                m = re.match(self.data.state_key_space +
                             '/([^/]+)/ports/([^/]+)$',
                             key)

                if m:
                    host = m.group(1)
                    port = m.group(2)

                    if action == 'delete':
                        # Nova doesn't much care when ports go away.
                        pass
                    else:
                        self.data.notify_bound(port, host)
                else:
                    # Matches a port key, gets host and uuid
                    m = re.match(self.data.state_key_space + '/([^/]+)/alive$',
                                 key)

                    if m:
                        # TODO(ijw): this should be fed into the agents
                        # table.
                        host = m.group(1)

                        if action == 'delete':
                            LOG.info('host %s has died', host)
                        else:
                            LOG.info('host %s is alive', host)
                    else:
                        LOG.warning('Unexpected key change in '
                                    'etcd port feedback: %s', key)

        ReturnWatcher(self.etcd_client, 'return_worker',
                      self.state_key_space, data=self).watch_forever()
