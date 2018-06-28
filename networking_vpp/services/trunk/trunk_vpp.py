#  Copyright (c) 2017 Cisco Systems, Inc.
#  All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
#

import copy
from networking_vpp import constants as nvpp_const
from networking_vpp.db import db
from networking_vpp.mech_vpp import EtcdAgentCommunicator

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import api as neutron_db_api
from neutron.db import common_db_mixin
from neutron.db import db_base_plugin_common

from neutron.objects import base as objects_base
from neutron.objects import trunk as trunk_objects

try:
    from neutron_lib.plugins import utils as plugin_utils
except ImportError:
    from neutron.plugins.common import utils as plugin_utils

from neutron.services.trunk import callbacks
from neutron.services.trunk import constants as trunk_const
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import rules

from oslo_log import log as logging
from oslo_utils import uuidutils

LOG = logging.getLogger(__name__)


def kick_communicator_on_end(func):
    # Give the etcd communicator a kick after the method returns
    def new_func(obj, *args, **kwargs):
        return_value = func(obj, *args, **kwargs)
        obj.communicator.kick()
        return return_value
    return new_func


class VppTrunkPlugin(common_db_mixin.CommonDbMixin):
    """Implementation of the VPP Trunk Service Plugin.

    This class implements the trunk service plugin that provides
    support for launching an instance on a vhostuser trunk port.
    """

    supported_extension_aliases = ["trunk", "trunk-details"]

    def __init__(self):
        super(VppTrunkPlugin, self).__init__()
        self.communicator = EtcdAgentCommunicator(
            notify_bound=lambda *args: None)
        # Supported segmentation type is VLAN
        self._segmentation_types = {
            trunk_const.VLAN: plugin_utils.is_valid_vlan_tag
            }
        registry.subscribe(self._trigger_trunk_update,
                           resources.PORT, events.AFTER_UPDATE)
        registry.notify(trunk_const.TRUNK_PLUGIN, events.AFTER_INIT, self)
        LOG.debug('vpp-trunk: vpp trunk service plugin has initialized')

    @classmethod
    def get_plugin_type(cls):
        return "trunk"

    def get_plugin_description(self):
        return "Trunk port service plugin for VPP"

    def validate_trunk(self, context, trunk):
        """Validate the input trunk data and return a valid trunk object."""
        trunk_details = trunk
        trunk_validator = rules.TrunkPortValidator(trunk['port_id'])
        trunk_details['port_id'] = trunk_validator.validate(context)
#         subports_validator = rules.SubPortsValidator(
#             self._segmentation_types, trunk['sub_ports'], trunk['port_id'])
#         trunk_details['sub_ports'] = subports_validator.validate(context)
        trunk_details['sub_ports'] = self.validate_subports(context,
                                                            trunk['sub_ports'],
                                                            trunk)
        return trunk_details

    def validate_subports(self, context, subports, trunk,
                          basic_validation=False, trunk_validation=True):
        """Validate subports data in the trunk and return a valid subport."""
        subports_validator = rules.SubPortsValidator(
            self._segmentation_types, subports, trunk['port_id'])
        subports = subports_validator.validate(
            context,
            basic_validation=basic_validation,
            trunk_validation=trunk_validation)
        return subports

    def _trunk_path(self, trunk_port_id):
        return nvpp_const.LEADIN + "/global/trunks/" + trunk_port_id

    @neutron_db_api.context_manager.writer
    def _write_trunk_journal(self, context, trunk_path, trunk_data):
        """Write the trunk journal to etcd."""
        LOG.info("trunk-service: writing trunk trunk interface journal for "
                 "trunk:%s", trunk_data)
        # Remove extra keys from trunk_data
        extra_keys = {'updated_at', 'id', 'port_id', 'created_at',
                      'created_at', 'revision_number'}
        if isinstance(trunk_data, dict):
            etcd_data = {k: trunk_data[k]
                         for k in set(trunk_data.keys()) - extra_keys}
        else:
            etcd_data = trunk_data
        db.journal_write(context.session, trunk_path, etcd_data)

    @db_base_plugin_common.convert_result_to_dict
    def _get_trunk_data(self, trunk_obj):
        """Create and return a trunk dict"""
        return trunk_obj

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_trunk(self, context, trunk_id, fields=None):
        return self._get_trunk(context, trunk_id)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_trunks(self, context, filters=None, fields=None, sorts=None,
                   limit=None, marker=None, page_reverse=None):
        """Return available trunks."""
        filters = filters or {}
        pager = objects_base.Pager(sorts=sorts, limit=limit,
                                   page_reverse=page_reverse, marker=marker)
        return trunk_objects.Trunk.get_objects(context, _pager=pager,
                                               **filters)

    def _get_trunk(self, context, trunk_id):
        """Return the trunk object or raise an exception if not found."""
        trunk_obj = trunk_objects.Trunk.get_object(context, id=trunk_id)
        if trunk_obj is None:
            raise trunk_exc.TrunkNotFound(trunk_id=trunk_id)
        return trunk_obj

    @kick_communicator_on_end
    def create_trunk(self, context, trunk):
        """Validate the trunk and write to etcd via the journal."""
        LOG.debug("Creating trunk %s", trunk)
        trunk = self.validate_trunk(context, trunk['trunk'])
        sub_ports = [trunk_objects.SubPort(
            context=context,
            port_id=p['port_id'],
            segmentation_id=p['segmentation_id'],
            segmentation_type=p['segmentation_type'])
            for p in trunk['sub_ports']]
        trunk_obj = trunk_objects.Trunk(
            context=context,
            admin_state_up=trunk.get('admin_state_up', True),
            id=uuidutils.generate_uuid(),
            name=trunk.get('name', ""),
            description=trunk.get('description', ""),
            project_id=trunk['tenant_id'],
            port_id=trunk['port_id'],
            status=trunk_const.ACTIVE_STATUS,
            sub_ports=sub_ports)
        with neutron_db_api.context_manager.writer.using(context):
            trunk_obj.create()
            payload = callbacks.TrunkPayload(context, trunk_obj.id,
                                             current_trunk=trunk_obj)
            registry.notify(trunk_const.TRUNK,
                            events.PRECOMMIT_CREATE, self,
                            payload=payload)
        registry.notify(trunk_const.TRUNK,
                        events.AFTER_CREATE, self,
                        payload=payload)
        trunk_data = self._get_trunk_data(trunk_obj)
        trunk_path = self._trunk_path(trunk['port_id'])
        self._write_trunk_journal(context, trunk_path, trunk_data)
        return trunk_obj

    def _trigger_trunk_update(self, resource, event, trigger, **kwargs):
        """Trigger trunk update on port update registry event."""
        LOG.debug("Triggering a trunk update with data %s", kwargs)
        trunk_details = kwargs['port'].get('trunk_details')
        if not trunk_details:
            return
        context = kwargs['context']
        trunk_id = trunk_details['trunk_id']
        self.update_trunk(context, trunk_id,
                          {'trunk': {'status': trunk_const.DOWN_STATUS}})

    def update_trunk(self, context, trunk_id, trunk):
        """Update the trunk port and notify the agent."""
        LOG.debug("Updating trunk %s trunk_id %s", trunk, trunk_id)
        trunk_data = trunk['trunk']
        with neutron_db_api.context_manager.writer.using(context):
            trunk_obj = self._get_trunk(context, trunk_id)
            original_trunk = copy.deepcopy(trunk_obj)
            trunk_obj.update_fields(trunk_data, reset_changes=True)
            trunk_obj.update()
            payload = callbacks.TrunkPayload(context, trunk_id,
                                             original_trunk=original_trunk,
                                             current_trunk=trunk_obj)
            registry.notify(trunk_const.TRUNK,
                            events.PRECOMMIT_UPDATE, self,
                            payload=payload)
        registry.notify(trunk_const.TRUNK,
                        events.AFTER_UPDATE, self,
                        payload=payload)
        trunk_data = self._get_trunk_data(trunk_obj)
        trunk_path = self._trunk_path(trunk_data['port_id'])
        self._write_trunk_journal(context, trunk_path, trunk_data)
        return trunk_obj

    @kick_communicator_on_end
    def delete_trunk(self, context, trunk_id):
        """Delete the trunk port."""
        LOG.debug("Deleting trunk_id %s", trunk_id)
        deleted_from_db = False
        with neutron_db_api.context_manager.writer.using(context):
            trunk = self._get_trunk(context, trunk_id)
            rules.trunk_can_be_managed(context, trunk)
            trunk_port_validator = rules.TrunkPortValidator(trunk.port_id)
            if not trunk_port_validator.is_bound(context):
                trunk.delete()
                deleted_from_db = True
                payload = callbacks.TrunkPayload(context, trunk_id,
                                                 original_trunk=trunk)
                registry.notify(trunk_const.TRUNK,
                                events.PRECOMMIT_DELETE, self,
                                payload=payload)
            else:
                raise trunk_exc.TrunkInUse(trunk_id=trunk_id)
        if deleted_from_db:
            registry.notify(trunk_const.TRUNK,
                            events.AFTER_DELETE, self,
                            payload=payload)
            trunk_path = self._trunk_path(trunk['port_id'])
            self._write_trunk_journal(context, trunk_path, None)

    @kick_communicator_on_end
    def add_subports(self, context, trunk_id, subports):
        """Add one or more subports to a trunk."""
        LOG.debug("Adding subports %s to trunk %s", subports, trunk_id)
        trunk = self._get_trunk(context, trunk_id)
        subports = subports['sub_ports']
        subports = self.validate_subports(context, subports, trunk,
                                          basic_validation=True)
        added_subports = []
        rules.trunk_can_be_managed(context, trunk)
        original_trunk = copy.deepcopy(trunk)
        # The trunk should not be in the ERROR_STATUS
        if trunk.status == trunk_const.ERROR_STATUS:
            raise trunk_exc.TrunkInErrorState(trunk_id=trunk_id)
        with neutron_db_api.context_manager.writer.using(context):
            for subport in subports:
                subport_obj = trunk_objects.SubPort(
                    context=context,
                    trunk_id=trunk_id,
                    port_id=subport['port_id'],
                    segmentation_type=subport['segmentation_type'],
                    segmentation_id=subport['segmentation_id'])
                subport_obj.create()
                trunk['sub_ports'].append(subport_obj)
                added_subports.append(subport_obj)
        # Write the journal if we have added subports
            payload = callbacks.TrunkPayload(context, trunk_id,
                                             current_trunk=trunk,
                                             original_trunk=original_trunk,
                                             subports=added_subports)
            if added_subports:
                registry.notify(trunk_const.SUBPORTS,
                                events.PRECOMMIT_CREATE,
                                self, payload=payload)
        if added_subports:
            registry.notify(trunk_const.SUBPORTS,
                            events.AFTER_CREATE,
                            self, payload=payload)
            trunk_data = self._get_trunk_data(trunk)
            trunk_path = self._trunk_path(trunk['port_id'])
            self._write_trunk_journal(context, trunk_path, trunk_data)
        return trunk

    @kick_communicator_on_end
    def remove_subports(self, context, trunk_id, subports):
        """Remove one or more subports from the trunk."""
        LOG.debug("Removing subports %s from trunk %s", subports, trunk_id)
        trunk = self._get_trunk(context, trunk_id)
        original_trunk = copy.deepcopy(trunk)
        subports = subports['sub_ports']
        subports = self.validate_subports(context, subports, trunk,
                                          basic_validation=True,
                                          trunk_validation=False)
        removed_subports = []
        rules.trunk_can_be_managed(context, trunk)
        # The trunk should not be in the ERROR_STATUS
        if trunk.status == trunk_const.ERROR_STATUS:
            raise trunk_exc.TrunkInErrorState(trunk_id=trunk_id)
        current_subports = {p.port_id: p for p in trunk.sub_ports}
        # Ensure that all sub-ports to be removed are actually present
        for subport in subports:
            if subport['port_id'] not in current_subports:
                raise trunk_exc.SubPortNotFound(trunk_id=trunk_id,
                                                port_id=subport['port_id'])
        with neutron_db_api.context_manager.writer.using(context):
            for subport in subports:
                subport_obj = current_subports.pop(subport['port_id'])
                subport_obj.delete()
                removed_subports.append(subport_obj)
            if removed_subports:
                del trunk.sub_ports[:]
                trunk.sub_ports.extend(current_subports.values())
                payload = callbacks.TrunkPayload(
                    context, trunk_id,
                    current_trunk=trunk,
                    original_trunk=original_trunk,
                    subports=removed_subports
                    )
                registry.notify(trunk_const.SUBPORTS,
                                events.PRECOMMIT_DELETE,
                                self, payload=payload)
        # Write journal if we have removed subports & notify registry
        if removed_subports:
            registry.notify(trunk_const.SUBPORTS,
                            events.AFTER_DELETE,
                            self, payload=payload)
            trunk_data = self._get_trunk_data(trunk)
            trunk_path = self._trunk_path(trunk['port_id'])
            self._write_trunk_journal(context, trunk_path, trunk_data)
        return trunk

    @db_base_plugin_common.filter_fields
    def get_subports(self, context, trunk_id, fields=None):
        trunk = self.get_trunk(context, trunk_id)
        return {'sub_ports': trunk['sub_ports']}
