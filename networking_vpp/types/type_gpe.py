# Copyright (c) 2013 OpenStack Foundation
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

from networking_vpp import config_opts
from networking_vpp import constants as nvpp_const
from networking_vpp import exceptions as nvpp_exc

from networking_vpp.compat import context as n_context
from networking_vpp.compat import driver_api
from networking_vpp.compat import n_exc
from networking_vpp.db.models import GpeAllocation

from neutron.db import api as db_api
from neutron.plugins.ml2.drivers import helpers
from oslo_config import cfg
from oslo_log import log as logging
from six import moves

LOG = logging.getLogger(__name__)


class GpeTypeDriver(helpers.SegmentTypeDriver):
    """A GPE network type driver.

    This class implements a type driver for tenant networks
    of type GPE. This driver is responsible for managing the
    VNI allocations and deallocations from a pool of VNIs.
    It enables overlay network connectivity between tenant
    instances using the GPE protocol.
    """

    def __init__(self):
        super(GpeTypeDriver, self).__init__(GpeAllocation)
        self.initialize()

    def get_type(self):
        return nvpp_const.TYPE_GPE

    def initialize(self):
        try:
            config_opts.register_vpp_opts(cfg.CONF)
            gpe_vni_ranges = cfg.CONF.ml2_vpp.gpe_vni_ranges
            self.segmentation_key = next(iter(self.primary_keys))
            # A list of VNI tuples:(min_vni, max_vni) available for allocation
            self.gpe_ranges = []
            self.gpe_ranges.extend(self._parse_gpe_vni_ranges(gpe_vni_ranges))
            self.sync_allocations()
        except nvpp_exc.GpeVNIRangeError(vni_range=gpe_vni_ranges):
            LOG.exception("Failed to parse gpe_vni_ranges from config. "
                          "Service terminated!")
            raise SystemExit()

    def _parse_gpe_vni_ranges(self, gpe_vni_ranges):
        """Parses a well formed GPE VNI range string.

        The GPE VNI ranges string is a comma-separated list of:
        <start_vni>:<end_vni> tuples that are available for tenant network
        allocation.
        It is set in the ml2_conf.ini file using the config option:
        gpe_vni_ranges = <start_vni>:<end_vni>   (or)
        gpe_vni_ranges = <start_vni>:<end_vni>, <start_vni>:<end_vni>
        :param:   gpe_vni_range: The GPE VNI range string to parse.
        :returns: A list of valid gpe_vni_range tuples
        """
        vni_ranges = []
        # String format: gpe_vni_ranges = 2000:3000,4000:5000
        LOG.debug('GPE driver parsing vni ranges: %s', gpe_vni_ranges)
        for entry in gpe_vni_ranges:
            try:
                min_vni, max_vni = entry.strip().split(':')
                vni_range = int(min_vni.strip()), int(max_vni.strip())
                self._verify_gpe_vni(vni_range)
                vni_ranges.append(vni_range)
            except ValueError:
                raise nvpp_exc.GpeVNIRangeError(vni_range=gpe_vni_ranges)
        return vni_ranges

    def _verify_gpe_vni(self, vni_or_vni_range):
        """Verify if the GPE VNI is valid.

        :param: vni_or_vni_range: An integer vni value or a tuple containing
        a vni_range value in the format (vni_min, vni_max).
        """
        if isinstance(vni_or_vni_range, tuple):
            vnis = list(vni_or_vni_range)
        else:
            vnis = []
            vnis.append(vni_or_vni_range)
        for vni in vnis:
            if not (nvpp_const.MIN_GPE_VNI <= int(vni)
                    <= nvpp_const.MAX_GPE_VNI):
                LOG.error("Invalid GPE VNI %s", vni)
                raise ValueError

    @db_api.retry_db_errors
    def sync_allocations(self):
        """Determine the currently allocatable GPE VNIs in the DB."""

        LOG.debug('gpe_type-driver: Syncing DB VNI allocations')
        ctx = n_context.get_admin_context()
        session = ctx.session
        valid_gpe_vnis = set()
        for min_vni, max_vni in self.gpe_ranges:
            valid_gpe_vnis |= set(moves.range(min_vni, max_vni + 1))

        with session.begin(subtransactions=True):
            # Current VNI allocations in DB
            allocs = (session.query(self.model).with_lockmode(
                'update').all())
            all_db_vnis = set([a.gpe_vni for a in allocs])
            # VNIs not in DB but newly added in the ML2 config
            missing_vnis = valid_gpe_vnis - all_db_vnis
            # Set of unallocated VNIs in the DB
            unallocated_vnis = set([a.gpe_vni for a in allocs if
                                    not a.allocated])
            # Remove unallocated VNIs from the DB that are invalid
            vnis_to_remove = unallocated_vnis - valid_gpe_vnis
            LOG.debug("gpe_type_driver: vnis to remove: %s", vnis_to_remove)
            LOG.debug("gpe_type_driver: vnis to add: %s", missing_vnis)
            # Remove any invalid VNIs
            for alloc in allocs:
                if alloc.gpe_vni in vnis_to_remove:
                    session.delete(alloc)
            # Add the missing GPE VNIs to the DB
            for vni in sorted(missing_vnis):
                alloc = self.model(gpe_vni=vni, allocated=False)
                session.add(alloc)

    def is_partial_segment(self, segment):
        return segment.get(driver_api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        network_type = segment.get(driver_api.NETWORK_TYPE)
        segmentation_id = segment.get(driver_api.SEGMENTATION_ID)
        for key, value in segment.items():
            if value and key not in [driver_api.NETWORK_TYPE,
                                     driver_api.SEGMENTATION_ID]:
                msg = (_("%(key)s prohibited for %(gpe)s network"),
                       {'key': key,
                        'gpe': network_type})
                raise n_exc.InvalidInput(error_message=msg)
        self._verify_gpe_vni(segmentation_id)

    def reserve_provider_segment(self, session, segment):
        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(session)
            if not alloc:
                raise n_exc.NoNetworkAvailable()
        else:
            segmentation_id = segment.get(driver_api.SEGMENTATION_ID)
            alloc = self.allocate_fully_specified_segment(
                session, **{self.segmentation_key: segmentation_id})
            if not alloc:
                raise nvpp_exc.GpeVNIInUse(vni_id=segmentation_id)

        return {driver_api.NETWORK_TYPE: self.get_type(),
                driver_api.PHYSICAL_NETWORK: None,
                driver_api.SEGMENTATION_ID: getattr(alloc,
                                                    self.segmentation_key),
                driver_api.MTU: self.get_mtu()}

    def allocate_tenant_segment(self, session):
        alloc = self.allocate_partially_specified_segment(session)
        if not alloc:
            return
        return {driver_api.NETWORK_TYPE: self.get_type(),
                driver_api.PHYSICAL_NETWORK: None,
                driver_api.SEGMENTATION_ID: getattr(alloc,
                                                    self.segmentation_key),
                driver_api.MTU: self.get_mtu()}

    def release_segment(self, context, segment):
        vni_id = segment[driver_api.SEGMENTATION_ID]
        LOG.debug('Releasing GPE segment %s', vni_id)
        valid = any(lo <= vni_id <= hi for lo, hi in self.gpe_ranges)

        info = {'type': self.get_type(), 'id': vni_id}
        with context.session.begin(subtransactions=True):
            query = (context.session.query(self.model).
                     filter_by(**{self.segmentation_key: vni_id}))
            if valid:
                count = query.update({"allocated": False})
                if count:
                    LOG.debug("Releasing %(type)s VNI %(id)s to pool",
                              info)
            else:
                count = query.delete()
                if count:
                    LOG.debug("Releasing %(type)s VNI %(id)s outside pool",
                              info)
        if not count:
            LOG.warning("%(type)s VNI %(id)s not found", info)

    def get_allocation(self, context, gpe_vni_id):
        return (context.session.query(self.model).
                filter_by(**{self.segmentation_key: gpe_vni_id}).first())

    def get_mtu(self, physical_network=None):
        mtu = super(GpeTypeDriver, self).get_mtu()
        return mtu - nvpp_const.GPE_ENCAP_OVERHEAD if mtu else 0
