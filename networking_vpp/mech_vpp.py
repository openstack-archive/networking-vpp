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
import os
from oslo_config import cfg
from oslo_log import log as logging
import re
import six
import time

from networking_vpp import compat
from networking_vpp.compat import context as n_context
from networking_vpp.compat import directory
from networking_vpp.compat import driver_api as api
from networking_vpp.compat import n_const
from networking_vpp.compat import plugin_constants
from networking_vpp.compat import portbindings
from networking_vpp import config_opts
from networking_vpp import constants as nvpp_const
from networking_vpp.db import db
from networking_vpp import etcdutils
from networking_vpp.ext_manager import ExtensionManager
from networking_vpp.extension import MechDriverExtensionBase

from networking_vpp.compat import events
from networking_vpp.compat import registry
from networking_vpp.compat import resources


try:
    # Newton and on
    from neutron.db.models import securitygroup
except ImportError:
    from neutron.db import securitygroups_db as securitygroup

try:
    # Newton (?) and on - prior to this we set state up, after this we
    # block ML2 from setting state to up
    from neutron.db import provisioning_blocks
except ImportError:
    global provisioning_blocks
    provisioning_blocks = None

# Liberty doesn't support precommit events.  We fix that here.
# 'commit time' is defined (by us alone) as 'when you should
# be using a callback to commit things'
try:
    CREATE_COMMIT_TIME = events.PRECOMMIT_CREATE
    UPDATE_COMMIT_TIME = events.PRECOMMIT_UPDATE
    DELETE_COMMIT_TIME = events.PRECOMMIT_DELETE
    PRECOMMIT = True
except AttributeError:
    # Liberty fallbacks:
    CREATE_COMMIT_TIME = events.AFTER_CREATE
    UPDATE_COMMIT_TIME = events.AFTER_UPDATE
    DELETE_COMMIT_TIME = events.AFTER_DELETE
    PRECOMMIT = False

LOG = logging.getLogger(__name__)


class VPPMechanismDriver(api.MechanismDriver):
    supported_vnic_types = [portbindings.VNIC_NORMAL]
    allowed_network_types = [plugin_constants.TYPE_FLAT,
                             plugin_constants.TYPE_VLAN,
                             nvpp_const.TYPE_GPE]
    MECH_NAME = 'vpp'

    def initialize(self):
        config_opts.register_vpp_opts(cfg.CONF)
        compat.register_securitygroups_opts(cfg.CONF)

        self.communicator = EtcdAgentCommunicator(self.port_bind_complete)

        names = names = cfg.CONF.ml2_vpp.driver_extensions
        if names is not '':
            self.mgr = ExtensionManager(
                'networking_vpp.driver.extensions',
                names,
                MechDriverExtensionBase)
            self.mgr.call_all('run', self.communicator)

    def get_vif_type(self, port_context):
        """Determine the type of the vif to be bound from port context"""

        # Default vif type
        vif_type = 'vhostuser'

        # We have to explicitly avoid binding agent ports - DHCP,
        # L3 etc. - as vhostuser. The interface code below takes
        # care of those.

        owner = port_context.current['device_owner']
        for f in n_const.DEVICE_OWNER_PREFIXES:
            if owner.startswith(f):
                vif_type = 'tap'
        LOG.debug("vif_type to be bound is: %s", vif_type)
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
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': port_context.current['id'],
                   'network': port_context.network.current['id']})
        vnic_type = port_context.current.get(portbindings.VNIC_TYPE,
                                             portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Refusing to bind due to unsupported "
                      "vnic_type: %s",
                      vnic_type)
            return

        for segment in port_context.segments_to_bind:
            if self.check_segment(segment, port_context.host):
                vif_details = {}
                # TODO(ijw) should be in a library that the agent uses
                vif_type = self.get_vif_type(port_context)
                if vif_type == 'vhostuser':
                    vif_details['vhostuser_socket'] = \
                        os.path.join(cfg.CONF.ml2_vpp.vhost_user_dir,
                                     port_context.current['id'])
                    vif_details['vhostuser_mode'] = 'server'
                LOG.debug('Setting details: %s', vif_details)
                port_context.set_binding(segment[api.ID],
                                         vif_type,
                                         vif_details)
                LOG.debug("Bind selected using segment: %s", segment)
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
                'Network %(network_id)s is %(network_type)s, '
                'but this driver only supports types '
                '%(allowed_network_types)s. '
                'The type must be supported  if binding is to succeed.',
                {'network_id': segment['id'],
                 'network_type': network_type,
                 'allowed_network_types':
                 ', '.join(self.allowed_network_types)}
            )
            return False

        if network_type in [plugin_constants.TYPE_FLAT,
                            plugin_constants.TYPE_VLAN]:
            physnet = segment[api.PHYSICAL_NETWORK]
            if not self.physnet_known(host, physnet):
                LOG.debug(
                    'Network %(network_id)s is on physical '
                    'network %(physnet)s, but the physical network '
                    'is not one the host %(host)s has attached.',
                    {'network_id': segment['id'],
                     'physnet': physnet,
                     'host': host}
                )
                return False

        return True

    def physnet_known(self, host, physnet):
        return self.communicator.find_physnet(host, physnet)

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

        # unbind port from old host, if already bound
        if port_context.original_binding_levels is not None:
            prev_bind = port_context.original_binding_levels[-1]

            if (prev_bind is not None and
                    prev_bind.get(api.BOUND_DRIVER) == self.MECH_NAME and
                    port_context.host != port_context.original_host):

                # Note that we skip this step if the change happens while
                # 'unbinding' and rebinding to the same host - it's probably
                # an update of extraneous detail and not really a request
                # that requires binding.

                self.communicator.unbind(port_context._plugin_context.session,
                                         port_context.original,
                                         port_context.original_host,
                                         prev_bind[api.BOUND_SEGMENT]
                                         )

        # (Re)bind port to the new host, if it needs to be bound
        if port_context.binding_levels is not None:
            current_bind = port_context.binding_levels[-1]

            if (current_bind is not None and
                    current_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):

                binding_type = self.get_vif_type(port_context)
                # Remove port membership from any previously associated
                # security groups for updating remote_security_group_id ACLs
                self.communicator.remove_port_from_remote_groups(
                    port_context._plugin_context.session,
                    port_context.original,
                    port_context.current)

                self.communicator.bind(port_context._plugin_context.session,
                                       port_context.current,
                                       current_bind[api.BOUND_SEGMENT],
                                       port_context.host,
                                       binding_type)

                # TODO(ijW): The agent driver checks for a change of
                # host, but we're oddly seeing that the orig_host is
                # always set.  Should confirm if this is a problem or
                # not.
                self._insert_provisioning_block(port_context)

    def port_bind_complete(self, port_id, host):
        """Tell things that the port is truly bound.

        This is a callback called by the etcd communicator.

        """
        LOG.debug('bind complete on %s', port_id)
        self._release_provisioning_block(host, port_id)

    def _insert_provisioning_block(self, context):
        if provisioning_blocks is None:
            # Functionality not available in this version of Neutron
            return

        # we insert a status barrier to prevent the port from transitioning
        # to active until the agent reports back that the wiring is done
        port = context.current
        if port['status'] == n_const.PORT_STATUS_ACTIVE:
            # no point in putting in a block if the status is already ACTIVE
            return

        provisioning_blocks.add_provisioning_component(
            context._plugin_context, port['id'], resources.PORT,
            provisioning_blocks.L2_AGENT_ENTITY)

    def _release_provisioning_block(self, host, port_id):
        context = n_context.get_admin_context()

        if provisioning_blocks is None:
            # Without provisioning_blocks support, it's our job (not
            # ML2's) to make the port active.
            plugin = directory.get_plugin()
            plugin.update_port_status(context, port_id,
                                      n_const.PORT_STATUS_ACTIVE, host)
        else:
            provisioning_blocks.provisioning_complete(
                context, port_id, resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY)

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
                self.communicator.kick()
            elif (prev_bind is not None and
                  prev_bind.get(api.BOUND_DRIVER) == self.MECH_NAME):
                self.communicator.kick()

    def delete_port_precommit(self, port_context):
        port = port_context.current
        host = port_context.host
        # NB: Host is typically '' if the port is not bound
        # A port can be in an invalid state with a host context
        if host and port_context.binding_levels:
            segment = port_context.binding_levels[-1][api.BOUND_SEGMENT]
            self.communicator.unbind(port_context._plugin_context.session,
                                     port, host, segment)

    def delete_port_postcommit(self, port_context):
        self.communicator.kick()


@six.add_metaclass(abc.ABCMeta)
class AgentCommunicator(object):

    @abstractmethod
    def bind(self, port, segment, host, binding_type):
        pass

    @abstractmethod
    def unbind(self, port, host):
        pass


# Our prefix for etcd keys, in case others are using etcd.
LEADIN = nvpp_const.LEADIN   # TODO(ijw): make configurable?
# Model for representing a security group
SecurityGroup = namedtuple(
    'SecurityGroup', ['id', 'ingress_rules', 'egress_rules']
    )
# Model for a VPP security group rule
SecurityGroupRule = namedtuple(
    'SecurityGroupRule', ['is_ipv6', 'remote_ip_addr',
                          'ip_prefix_len', 'remote_group_id',
                          'protocol', 'port_min', 'port_max']
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
    # Port Space
    LEADIN/nodes - subdirs are compute nodes
    LEADIN/nodes/X/ports - entries are JSON-ness containing
    all information on each bound port on the compute node.
    (Unbound ports are homeless, so the act of unbinding is
    the deletion of this entry.)
    # Global Space
    LEADIN/global/secgroups/<security-group-id> - entries are security-group
    keys whose values contain all the rule data
    LEADIN/global/networks/gpe/<vni>/<hostname>/<mac>/<ip-address> - Entries
    contain GPE data such as the VNI, hostname, instance's mac & IP address
    and key value is the underlay IP address of the compute node
    LEADIN/global/remote_group/<group-id>/<port-id> contain the IP addresses
    of ports in a security-group
    # State Space
    LEADIN/state/X - return state of the VPP
    LEADIN/state/X/alive - heartbeat back
    LEADIN/state/X/ports - port information.
    LEADIN/state/X/physnets - physnets on node
    Specifically a key here (regardless of value) indicates
    the port has been bound and is receiving traffic.
    """

    def __init__(self, notify_bound):
        super(EtcdAgentCommunicator, self).__init__()
        LOG.debug("Using etcd host:%s port:%s user:%s",
                  cfg.CONF.ml2_vpp.etcd_host,
                  cfg.CONF.ml2_vpp.etcd_port,
                  cfg.CONF.ml2_vpp.etcd_user)

        # This is a function that is called when a port has been
        # notified from the agent via etcd as completely attached.

        # We call this when we're certain that the VPP on the far end
        # has definitely bound the port, and has dropped a vhost-user
        # socket where it can be found.

        # This is more important than it seems, becaus libvirt will
        # hang, because qemu ignores its monitor port, when qemu is
        # waiting for a partner to connect with on its vhost-user
        # interfaces.  It can't start the VM - that requires
        # information from its partner it can't guess at - but it
        # shouldn't hang the monitor - nevertheless...  So we notify
        # when the port is there and ready, and qemu is never put into
        # this state by Nova.
        self.notify_bound = notify_bound

        self.client_factory = etcdutils.EtcdClientFactory(cfg.CONF.ml2_vpp)

        # For Liberty support, we have to have a memory between notifications
        self.deleted_rule_secgroup_id = {}

        # We need certain directories to exist
        self.state_key_space = LEADIN + '/state'
        self.port_key_space = LEADIN + '/nodes'
        self.secgroup_key_space = LEADIN + '/global/secgroups'
        self.remote_group_key_space = LEADIN + '/global/remote_group'
        self.gpe_key_space = LEADIN + '/global/networks/gpe'
        self.election_key_space = LEADIN + '/election'
        self.journal_kick_key = self.election_key_space + '/kick-journal'

        etcd_client = self.client_factory.client()
        etcd_helper = etcdutils.EtcdHelper(etcd_client)
        etcd_helper.ensure_dir(self.state_key_space)
        etcd_helper.ensure_dir(self.port_key_space)
        etcd_helper.ensure_dir(self.secgroup_key_space)
        etcd_helper.ensure_dir(self.election_key_space)
        etcd_helper.ensure_dir(self.remote_group_key_space)

        self.secgroup_enabled = cfg.CONF.SECURITYGROUP.enable_security_group
        if self.secgroup_enabled:
            self.register_secgroup_event_handler()

        # TODO(ijw): .../state/<host> lists all known hosts, and they
        # heartbeat when they're functioning

        # From this point on, there are multiple threads: ensure that
        # we don't re-use the etcd_client from multiple threads
        # simultaneously
        etcd_helper = None
        etcd_client = None

        try:
            # Liberty, Mitaka
            ev = events.AFTER_INIT
        except Exception:
            # Newton and on
            ev = events.AFTER_CREATE

        registry.subscribe(self.start_threads, resources.PROCESS, ev)

    def start_threads(self, resource, event, trigger):
        LOG.debug('Starting background threads for Neutron worker')
        self.return_thread = self.make_return_worker()
        self.forward_thread = self.make_forward_worker()

    def find_physnet(self, host, physnet):
        """Identify if an agent can connect to the physical network

        This can fail if the agent hasn't been configured for that
        physnet, or if the agent isn't alive.
        """

        # TODO(ijw): we use an on-the-fly created client so that we
        # don't have threading problems from the caller.
        try:
            etcd_client = self.client_factory.client()

            etcd_client.read('%s/state/%s/alive' % (LEADIN, host))
            etcd_client.read('%s/state/%s/physnets/%s' %
                             (LEADIN, host, physnet))
        except etcd.EtcdKeyNotFound:
            return False
        return True

    def register_secgroup_event_handler(self):
        """Subscribe a handler to process secgroup change notifications

        We're interested in PRECOMMIT_xxx (where we store the changes
        to etcd in the journal table) and AFTER_xxx (where we
        remind the worker thread it may have work to do).
        """

        LOG.info("Security groups feature is enabled")

        # NB security group rules cannot be updated, and security
        # groups themselves have no forwarder state in them, so we
        # don't need the update events

        # register pre-commit events if they're available
        if PRECOMMIT:
            # security group precommit events
            registry.subscribe(self.process_secgroup_commit,
                               resources.SECURITY_GROUP,
                               events.PRECOMMIT_CREATE)
            registry.subscribe(self.process_secgroup_commit,
                               resources.SECURITY_GROUP,
                               events.PRECOMMIT_DELETE)
            # security group rule precommit events
            registry.subscribe(self.process_secgroup_commit,
                               resources.SECURITY_GROUP_RULE,
                               events.PRECOMMIT_CREATE)
            registry.subscribe(self.process_secgroup_commit,
                               resources.SECURITY_GROUP_RULE,
                               events.PRECOMMIT_DELETE)

        # register post-commit events
        # security group post commit events
        registry.subscribe(self.process_secgroup_after,
                           resources.SECURITY_GROUP,
                           events.AFTER_CREATE)
        registry.subscribe(self.process_secgroup_after,
                           resources.SECURITY_GROUP,
                           events.AFTER_DELETE)
        # security group rule post commit events
        registry.subscribe(self.process_secgroup_after,
                           resources.SECURITY_GROUP_RULE,
                           events.AFTER_CREATE)
        registry.subscribe(self.process_secgroup_after,
                           resources.SECURITY_GROUP_RULE,
                           events.AFTER_DELETE)

        if not PRECOMMIT:
            # Liberty requires a BEFORE_DELETE hack
            registry.subscribe(self.process_secgroup_commit,
                               resources.SECURITY_GROUP_RULE,
                               events.BEFORE_DELETE)

    def process_secgroup_after(self, resource, event, trigger, **kwargs):
        """Callback for handling security group/rule commit-complete events

        This is when we should tell other things that a change has
        happened and has been recorded permanently in the DB.
        """
        # In Liberty, this is the only callback that's called.
        # We use our own event names, which will identify AFTER_*
        # events as the right time to commit, so in this case we
        # simply call the commit function ourselves.

        # This is not perfect - since we're not committing in one
        # transaction we can commit the secgroup change but fail to
        # propagate it to the journal and from there  to etcd on a
        # crash.  It's all we can do for Liberty as it doesn't support
        # in-transaction precommit events.
        if not PRECOMMIT:
            self.process_secgroup_commit(resource, event, trigger, **kwargs)

        # Whatever the object that caused this, we've put something
        # in the journal and now need to nudge the communicator
        self.kick()

    def process_secgroup_commit(self, resource, event, trigger, **kwargs):
        """Callback for handling security group/rule  commit events

        This is the time at which we should be committing any of our
        own auxiliary changes to the DB.
        """
        LOG.debug("Received event %s notification for resource"
                  " %s with kwargs %s", event, resource, kwargs)
        context = kwargs['context']

        # Whatever we're working from should have a resource ID
        # in this form, if it exists at all.  Alternatively, it may
        # be that there's no ID (because the row is freshly created).
        res = kwargs.get(resource)
        res_id = kwargs.get("%s_id" % resource)
        if res_id is None:
            res_id = res.get('id')

        new_objects = context.session.new

        changed_sgids = []
        deleted_rules = []

        if resource == resources.SECURITY_GROUP:
            if event == DELETE_COMMIT_TIME:
                self.delete_secgroup_from_etcd(context.session,
                                               kwargs['security_group_id'])
            elif event == CREATE_COMMIT_TIME:
                # When Neutron creates a security group it also
                # attaches rules to it.  We need to sync the rules.

                # Also, the SG passed to us is what comes in from the user.
                # We require what went into the DB (where we added a UUID
                # to it).

                if res_id is None:
                    # New objects do not have their resource ID assigned
                    changed_sgids = \
                        [sg.id for sg in new_objects
                            if isinstance(sg, securitygroup.SecurityGroup)]
                else:
                    changed_sgids = [res_id]

        elif resource == resources.SECURITY_GROUP_RULE:
            # We store security groups with a composite of all their
            # rules.  So in this case we track down the affected
            # rule and update its entire data.
            # NB: rules are never updated.
            if event == events.BEFORE_DELETE:
                # This is a nasty little hack to add required information
                # so that the AFTER_DELETE trigger can have it
                # Fortunately the events described are all called from the
                # one DB function and we will see all of them in the one
                # process.  We use a dict in case multiple threads are
                # working.  Only one of them will get to the AFTER if they're
                # working on the one rule.
                # This is ugly.  Liberty support is ugly.
                rule = self.get_secgroup_rule(res_id, context)
                self.deleted_rule_secgroup_id[res_id] = \
                    rule['security_group_id']

            if event == DELETE_COMMIT_TIME:

                if PRECOMMIT:
                    # This works for PRECOMMIT triggers, where the rule
                    # is in the DB still
                    rule = self.get_secgroup_rule(res_id, context)
                    changed_sgids = [rule['security_group_id']]
                else:
                    # This works for AFTER_DELETE triggers (Liberty)
                    # but only because we saved it in BEFORE_DELETE
                    changed_sgids = [self.deleted_rule_secgroup_id[res_id]]
                    # Clean up to keep the dict size down
                    del self.deleted_rule_secgroup_id[res_id]

                deleted_rules.append(res_id)

            elif event == CREATE_COMMIT_TIME:
                # Groups don't have the same UUID problem - we're not
                # using their UUID, we're using their SG's, which must
                # be present.
                rule = kwargs['security_group_rule']
                changed_sgids = [rule['security_group_id']]

        if changed_sgids:
            self.send_sg_updates(context,
                                 changed_sgids,
                                 deleted_rules=deleted_rules)

    def send_sg_updates(self, context, sgids, deleted_rules=None):
        """Called when security group rules are updated

        Arguments:
        sgs - A list of one or more security group IDs
        context - The plugin context i.e. neutron.context.Context object
        deleted_rules - An optional list of deleted rules

        1. Read security group rules from neutron DB
        2. Build security group objects from their rules
        3. Write secgroup to the secgroup_key_space in etcd
        """

        if deleted_rules is None:
            deleted_rules = []

        plugin = directory.get_plugin()
        with context.session.begin(subtransactions=True):
            for sgid in sgids:
                rules = plugin.get_security_group_rules(
                    context, filters={'security_group_id': [sgid]}
                    )

                # If we're in the precommit part, we may have deleted
                # rules in this list and we should exclude them
                rules = (r for r in rules if r['id'] not in deleted_rules)

                # Get the full details of the secgroup in exchange format
                secgroup = self.get_secgroup_from_rules(sgid, rules)

                # Write security group data to etcd
                self.send_secgroup_to_agents(context.session, secgroup)

    def get_secgroup_rule(self, rule_id, context):
        """Fetch and return a security group rule from Neutron DB"""
        plugin = directory.get_plugin()
        with context.session.begin(subtransactions=True):
            return plugin.get_security_group_rule(context, rule_id)

    def get_secgroup_from_rules(self, sgid, rules):
        """Build and return a security group namedtuple object.

        This object is the format with which we exchange data with
        the agents, and can be written in this form to etcd.

        Arguments:
        sgid - ID of the security group
        rules - A list of security group rules as returned from the DB

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

    # Neutron supports the following IP protocols by name
    protocols = {'tcp': 6, 'udp': 17, 'icmp': 1, 'icmpv6': 58,
                 'ah': 51, 'dccp': 33, 'egp': 8, 'esp': 50, 'gre': 47,
                 'igmp': 2, 'ipv6-encap': 41, 'ipv6-frag': 44,
                 'ipv6-icmp': 58, 'ipv6-nonxt': 59, 'ipv6-opts': 60,
                 'ipv6-route': 43, 'ospf': 89, 'pgm': 113, 'rsvp': 46,
                 'sctp': 132, 'udplite': 136,
                 'vrrp': 112}

    def _neutron_rule_to_vpp_acl(self, rule):
        """Convert a neutron rule to vpp_acl rule.

        Arguments:
        1. rule -- represents a neutron rule

        - Convert the neutron rule to a vpp_acl rule model
        - Return the SecurityGroupRule namedtuple.
        """
        is_ipv6 = 0 if rule['ethertype'] == 'IPv4' else 1

        if rule['protocol'] is None:
            # Neutron uses None to represent any protocol
            # We use 0 to represent any protocol
            protocol = 0
        elif rule['protocol'] in self.protocols:
            # VPP rules require IANA protocol numbers
            # Convert input accordingly.
            protocol = self.protocols[rule['protocol']]
        else:
            # Convert incoming string value to an integer
            protocol = int(rule['protocol'])

        if is_ipv6 and protocol == self.protocols['icmp']:
            protocol = self.protocols['icmpv6']

        # Neutron represents any ip address by setting
        # both the remote_ip_prefix and remote_group_id fields to None
        # VPP uses all zeros to represent any Ipv4/IpV6 address
        # In a neutron security group rule, you can either set the
        # remote_ip_prefix or remote_group_id but not both.
        # When a remote_ip_prefix value is set, the remote_group_id
        # is ignored and vice versa. If both the attributes are unset,
        # any remote_ip_address is permitted.
        if rule['remote_ip_prefix']:
            remote_ip_addr, ip_prefix_len = rule['remote_ip_prefix'
                                                 ].split('/')
            ip_prefix_len = int(ip_prefix_len)
            # Set the required attribute, referenced by the SecurityGroupRule
            # tuple, remote_group_id to None.
            remote_group_id = None
        elif rule['remote_group_id']:
            remote_group_id = rule['remote_group_id']
            # Set remote_ip_addr and ip_prefix_len to empty values
            # as it is a required attribute referenced by the
            # SecurityGroupRule tuple. When the remote_ip_addr value is set
            # to None, the vpp-agent ignores it and looks at the
            # remote-group-id. One of these attributes must be set to a valid
            # value.
            remote_ip_addr, ip_prefix_len = None, 0
        else:
            # In neutron, when both the remote_ip_prefix and remote-group-id
            # are set to None, it implies permit any. But we need to set a
            # valid value for the remote_ip_address attribute to tell the
            # vpp-agent.
            remote_ip_addr = '0.0.0.0' if not is_ipv6 else '::'
            ip_prefix_len = 0
            # Set the required attribute in the SecurityGroupRule tuple
            # remote_group_id to None.
            remote_group_id = None
        # Neutron uses -1 or None or 0 to represent all ports
        # VPP uses 0-65535 for all tcp/udp ports, Use -1 to represent all
        # ranges for ICMP types and codes
        if rule['port_range_min'] == -1 or not rule['port_range_min']:
            # Valid TCP/UDP port ranges for TCP(6), UDP(17) and UDPLite(136)
            if protocol in [6, 17, 136]:
                port_min, port_max = (0, 65535)
            # A Value of -1 represents all ICMP/ICMPv6 types & code ranges
            elif protocol in [1, 58]:
                port_min, port_max = (-1, -1)
            # Ignore port_min and port_max fields as other protocols don't
            # use them
            else:
                port_min, port_max = (0, 0)
        else:
            port_min, port_max = (rule['port_range_min'],
                                  rule['port_range_max'])

        # Handle a couple of special ICMP cases
        if protocol in [1, 58]:
            # All ICMP types and codes
            if rule['port_range_min'] is None:
                port_min, port_max = (-1, -1)
            # All codes for a specific type
            elif rule['port_range_max'] is None:
                port_min, port_max = (rule['port_range_min'], -1)

        sg_rule = SecurityGroupRule(is_ipv6, remote_ip_addr,
                                    ip_prefix_len,
                                    remote_group_id, protocol, port_min,
                                    port_max)
        return sg_rule

    def send_secgroup_to_agents(self, session, secgroup):
        """Writes a secgroup to the etcd secgroup space

        Does this via the journal as part of the commit, so
        that the write is atomic with the DB commit to the
        Neutron tables.

        Arguments:
        session  -- the DB session with an open transaction
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
        db.journal_write(session, secgroup_path, sg)

    def delete_secgroup_from_etcd(self, session, secgroup_id):
        """Deletes the secgroup key from etcd

        Arguments:
        secgroup_id -- The id of the security group that we want to delete
        """
        secgroup_path = self._secgroup_path(secgroup_id)
        # Delete the security-group from remote-groups
        remote_group_path = self._remote_group_path(secgroup_id, '')
        db.journal_write(session, secgroup_path, None)
        db.journal_write(session, remote_group_path, None)

    def _secgroup_path(self, secgroup_id):
        return self.secgroup_key_space + "/" + secgroup_id

    def _port_path(self, host, port):
        return self.port_key_space + "/" + host + "/ports/" + port['id']

    # TODO(najoy): Move all security groups related code to a dedicated
    # module
    def _remote_group_path(self, secgroup_id, port_id):
        return self.remote_group_key_space + "/" + secgroup_id + "/" + port_id

    def _gpe_remote_path(self, host, port, segmentation_id):
        ip_addrs = port.get('fixed_ips', [])
        gpe_dir = self.gpe_key_space + "/" + str(segmentation_id) + "/" + \
            host + "/" + port['mac_address']
        if ip_addrs and segmentation_id:
            # Delete all GPE keys and the empty GPE directory itself in etcd
            return [gpe_dir + "/" + ip_address['ip_address']
                    for ip_address in ip_addrs] + [gpe_dir]
        else:
            return []

    # A remote_group_path is qualified with a port ID because the agent uses
    # the port ID to keep track of the dynamic set of ports associated with
    # the remote_group_id. The value of this key is the
    # list of IP addresses allocated to that port by neutron.
    # Using the above two pieces of information, the vpp-agent
    # computes the complete set of IP addresses belonging to a
    # remote_group_id and uses it to expand the rule when a remote_group_id
    # attribute is specified. The expansion is performed by computing a
    # product using all the IP addresses of the ports in the remote_group
    # and the remaining attributes of the rule.
    def _remote_group_paths(self, port):
        security_groups = port.get('security_groups', [])
        return [self._remote_group_path(secgroup_id, port['id'])
                for secgroup_id in security_groups]

    ######################################################################
    # These functions use a DB journal to log messages before
    # they're put into etcd, as that can take time and may not always
    # succeed (so is a bad candidate for calling within or after a
    # transaction).

    def kick(self):
        # A thread in one Neutron process - possibly not this one -
        # is waiting to send updates from the DB to etcd.  Wake it.
        try:
            # TODO(ijw): got to be a more efficient way to create
            # a client for each thread
            # From a Neutron thread, we need to tell whichever of the
            # forwarder threads that is active that it has work to do.
            self.client_factory.client().write(self.journal_kick_key, '')
        except etcd.EtcdException:
            # A failed wake is not the end of the world.
            pass

    def bind(self, session, port, segment, host, binding_type):
        # NB segmentation_id is not optional in the wireline protocol,
        # we just pass 0 for unsegmented network types
        data = {
            'mac_address': port['mac_address'],
            'mtu': 1500,  # not this, but what?: port['mtu'],
            'physnet': segment[api.PHYSICAL_NETWORK],
            'network_type': segment[api.NETWORK_TYPE],
            'segmentation_id': segment.get(api.SEGMENTATION_ID, 0),
            'binding_type': binding_type,
            'security_groups': port.get('security_groups', []),
            'allowed_address_pairs': port.get('allowed_address_pairs', []),
            'fixed_ips': port.get('fixed_ips', []),
            'port_security_enabled': port.get('port_security_enabled', True),
            # Non-essential, but useful for monitoring and debug:
            'device_id': port.get('device_id', None)
        }
        LOG.debug("Queueing bind request for port:%s, "
                  "segment:%s, host:%s, type:%s",
                  port, data['segmentation_id'],
                  host, data['binding_type'])

        db.journal_write(session, self._port_path(host, port), data)
        # For tracking ports in a remote_group, create a journal entry in
        # the remote-group key-space.
        # This will result in the creation of an etcd key with the port ID
        # and it's security-group-id. The value is the list of IP addresses.
        # For details on how the agent thread handles the remote-group
        # watch events refer to the doc under RemoteGroupWatcher in the
        # server module.
        for remote_group_path in self._remote_group_paths(port):
            db.journal_write(session, remote_group_path,
                             [item['ip_address'] for item in
                              data['fixed_ips']])
        self.kick()

    def unbind(self, session, port, host, segment):
        # GPE requires segmentation ID for removing its etcd keys
        segmentation_id = segment.get(api.SEGMENTATION_ID, 0)
        LOG.debug("Queueing unbind request for port:%s, host:%s, segment:%s",
                  port, host, segmentation_id)
        # When a port is unbound, this journal entry will delete the
        # port key (and hence it's ip address value) from etcd. The behavior
        # is like removing the port IP address(es) from the
        # remote-group. The agent will receive a watch notification and
        # update the ACL rules to remove the IP(s) from the rule.
        # Other port IP addresses associated with the remote-group-id will
        # remain in the rule (as it should be).
        # A hypothetical alternate implementation - If we made the remote key
        # of a secgroup, a list of IPs, we could refresh the content of
        # every secgroup containing this port.
        # It makes the sender's work harder, and receiver's work easier
        # In the sender, we need keep track of IPs during port binds, unbinds,
        # security-group associations and updates. However, algorithmically
        # this alternate impl. won't be better what we have now i.e. O(n).
        for remote_group_path in self._remote_group_paths(port):
            db.journal_write(session, remote_group_path, None)
        db.journal_write(session, self._port_path(host, port), None)
        # Remove all GPE remote keys from etcd, for this port
        for gpe_remote_path in self._gpe_remote_path(host, port,
                                                     segmentation_id):
            db.journal_write(session,
                             gpe_remote_path,
                             None)
        self.kick()

    def remove_port_from_remote_groups(self, session, original_port,
                                       current_port):
        """Remove ports from remote groups when port security is updated."""
        removed_sec_groups = set(original_port['security_groups']) - set(
            current_port['security_groups'])
        for secgroup_id in removed_sec_groups:
            db.journal_write(session,
                             self._remote_group_path(secgroup_id,
                                                     current_port['id']),
                             None)
        self.kick()

    ######################################################################
    # The post-journal part of the work that clears out the table and
    # updates etcd.

    def make_forward_worker(self):
        # Assign a UUID to each worker thread to enable thread election
        return eventlet.spawn(self._forward_worker)

    def do_etcd_update(self, etcd_writer, k, v):
        with eventlet.Timeout(cfg.CONF.ml2_vpp.etcd_write_time, False):
            if v is None:
                etcd_writer.delete(k)
            else:
                etcd_writer.write(k, v)

    def _forward_worker(self):
        LOG.debug('forward worker begun')
        etcd_client = self.client_factory.client()
        etcd_writer = etcdutils.json_writer(etcd_client)
        lease_time = cfg.CONF.ml2_vpp.forward_worker_master_lease_time
        recovery_time = cfg.CONF.ml2_vpp.forward_worker_recovery_time

        etcd_election = etcdutils.EtcdElection(etcd_client, 'forward_worker',
                                               self.election_key_space,
                                               work_time=lease_time,
                                               recovery_time=recovery_time)
        while True:
            # Try indefinitely to regain the mastery of this thread pool. Most
            # threads will be sitting here
            etcd_election.wait_until_elected()
            try:
                # Master loop - as long as we are master and can
                # maintain it, process incoming events.

                # Every long running section is preceded by extending
                # mastership of the thread pool and followed by
                # confirmation that we still have mastership (usually
                # by a further extension).

                def work(k, v):
                    self.do_etcd_update(etcd_writer, k, v)

                # We will try to empty the pending rows in the DB
                while True:
                    etcd_election.extend_election(
                        cfg.CONF.ml2_vpp.db_query_time)
                    session = n_context.get_admin_context().session
                    maybe_more = db.journal_read(session, work)
                    if not maybe_more:
                        LOG.debug('forward worker has emptied journal')
                        etcd_election.extend_election(lease_time)
                        break

                # work queue is now empty.

                # Wait to be kicked, or (in case of emergency) run
                # every few seconds in case another thread or process
                # dumped work and failed to get notification to us to
                # process it.
                with eventlet.Timeout(lease_time + 1, False):
                    etcd_election.extend_election(lease_time)
                    try:
                        etcd_client.watch(self.journal_kick_key,
                                          timeout=lease_time)
                    except etcd.EtcdException:
                        # Check the DB queue now, anyway
                        pass
            except etcdutils.EtcdElectionLost:
                # We are no longer master
                pass
            except Exception as e:
                # TODO(ijw): log exception properly
                LOG.warning("problems in forward worker - Error name is %s. "
                            "proceeding without quiting", type(e).__name__)
                LOG.warning("Exception in forward_worker: %s", e)
                # something went bad; breathe, in case we end
                # up in a tight loop
                time.sleep(1)
                # never quit
                pass

    ######################################################################

    def make_return_worker(self):
        """The thread that manages data returned from agents via etcd."""

        # TODO(ijw): agents and physnets should be checked before a bind
        # is accepted

        # Note that the initial load is done before spawning the background
        # watcher - this means that we're prepared with the information
        # to accept bind requests.

        class ReturnWatcher(etcdutils.EtcdChangeWatcher):

            def __init__(self, etcd_client, name, watch_path,
                         election_path=None, data=None):
                super(ReturnWatcher, self).__init__(etcd_client,
                                                    name, watch_path,
                                                    election_path,
                                                    wait_until_elected=True,
                                                    data=data)

            # Every key changes on a restart, which has the
            # useful effect of resending all Nova notifications
            # for 'port bound' events based on existing state.
            def added(self, key, value):
                # Matches a port key, gets host and uuid
                m = re.match('^([^/]+)/ports/([^/]+)$', key)

                if m:
                    host = m.group(1)
                    port = m.group(2)

                    self.data.notify_bound(port, host)
                else:
                    # Matches an agent, gets a liveness notification
                    m = re.match(self.data.state_key_space + '^([^/]+)/alive$',
                                 key)

                    if m:
                        # TODO(ijw): this should be fed into the agents
                        # table.
                        host = m.group(1)

                        LOG.info('host %s is alive', host)

            def removed(self, key):
                # Nova doesn't much care when ports go away.

                # Matches an agent, gets a liveness notification
                m = re.match(self.data.state_key_space + '^([^/]+)/alive$',
                             key)

                if m:
                    # TODO(ijw): this should be fed into the agents
                    # table.
                    host = m.group(1)

                    LOG.info('host %s has died', host)

        # Assign a UUID to each worker thread to enable thread election
        return eventlet.spawn(
            ReturnWatcher(self.client_factory.client(), 'return_worker',
                          self.state_key_space, self.election_key_space,
                          data=self).watch_forever)
