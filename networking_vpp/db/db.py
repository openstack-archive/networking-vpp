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

from networking_vpp.db import models

import sqlalchemy as sa
from sqlalchemy.sql.expression import func

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def journal_read(session, func):
    """Read, process and delete (if successful) the oldest journal row.

    The row is locked on read, and remains locked until the processing
    succeeds or gives up.  This is to ensure that (in a multithreaded
    or multiprocess environment) only one worker processes the update,
    which in turn ensures monotonicity.
    """

    # TODO(ijw): start a transaction here

    # Find and lock the oldest journal entry

    # NB this will serialise on locking the oldest record if there are
    # multiple threads running (as there may be if multiple processes
    # are running)

    maybe_more = True

    # TODO(ijw): not true, check with Arvind
    # Set subtransactions to True otherwise this generates a failure
    # in the L3 plugin API. This is invoked from within the greater
    # create/delete router API call and we ideally want both to pass or
    # fail together.

    # Find the lowest ID'd row in the table. We assume that the ID is
    # a time ordering. We are only scanning for it now, not locking yet.
    entry = session.query(models.VppEtcdJournal) \
                   .order_by(models.VppEtcdJournal.id) \
                   .first()

    if not entry:
        return False  # Signal that we nothing more to do
    else:
        with session.begin(subtransactions=True):
            try:
                first_id = entry.id
                # Reselect with a lock, but without doing the range check
                # so that the lock is row-specific
                rs = session.query(models.VppEtcdJournal)\
                    .filter(models.VppEtcdJournal.id == first_id)\
                    .with_for_update().all()

                if len(rs) > 0:
                    # The entry is still around, and we are still master
                    entry = rs[0]
                    try:
                        func(entry.k, entry.v)  # do work, could fail
                        session.delete(entry)  # This is now processed
                        LOG.debug('forwarded etcd record %d', first_id)
                    except Exception as e:
                        # For some reason, we can't do the job.
                        entry.retry_count += 1
                        entry.last_retried = sa.func.now()
                        entry.update(entry)
                        LOG.warning("Couldn't forward etcd record %d due to"
                                    " exception %s. retrying later",
                                    first_id, type(e).__name__)
                else:
                    # We cannot find that entry any more, means some other
                    # master kicking around. Should be rare
                    # TODO(ijw): We should re-elect ourselves if we can
                    maybe_more = False
                    LOG.debug("etcd record %d processed by "
                              "another forwarder", first_id)
            except Exception as e:
                LOG.exception("forward worker journal read processing hit "
                              "error. Error is: %s", e)

    return maybe_more


def journal_write(session, k, v):
    """Write a new journal entry.

    This is expected to be used in the precommit, so is a part of a
    larger transaction.  It doesn't commit itself.
    """
    entry = models.VppEtcdJournal(k=k, v=v)
    session.add(entry)
    session.flush()


def get_all_journal_rows(session):
    """Returns all journal rows in the DB.

    This method returns all rows in the journal table, this is mainly
    used in unit tests.
    """
    return session.query(
        models.VppEtcdJournal).order_by(
        models.VppEtcdJournal.id).all()


def add_router_vrf(session, router_id):
    """Allocates a new VRF to a router.

    This method finds the highest extant VRF number from the DB and
    allocates a new VRF id = highest + 1 to the router requested.
    """
    with session.begin(subtransactions=True):
        # Get the highest VRF number in the DB
        new_vrf = session.query(
            func.max(models.VppRouterVrf.vrf_id)).scalar() or 0
        new_vrf += 1

        row = models.VppRouterVrf(router_id=router_id, vrf_id=new_vrf)
        session.add(row)

    return new_vrf


def get_router_vrf(session, router_id):
    # Returns a VRF id for the specified router id
    row = session.query(
        models.VppRouterVrf).filter_by(router_id=router_id).one_or_none()
    if row:
        return row.vrf_id

    return None


def delete_router_vrf(session, router_id):
    # Removes VRF allocation for the specified router id
    with session.begin(subtransactions=True):
        row = session.query(
            models.VppRouterVrf).filter_by(
            router_id=router_id).one_or_none()

        if row:
            session.delete(row)
            session.flush()
