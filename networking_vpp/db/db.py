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
    with session.begin(subtransactions=True):
        # Note also that this will, if the other thread succeeds, lock a
        # row that someone else deletes, so its session will abort.
        entry = session.query(models.VppEtcdJournal) \
                       .order_by(models.VppEtcdJournal.id) \
                       .with_for_update() \
                       .first()

        if entry:
            if func(entry.k, entry.v):  # ... can quite reasonably fail...
                # Once done, it should go.
                session.delete(entry)
            else:
                # For some reason, we can't do the job.
                entry.retry_count = entry.retry_count + 1
                entry.update(entry)

        else:
            # The table is empty - no work available.
            maybe_more = False

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
    return session.query(
        models.VppEtcdJournal).order_by(
        models.VppEtcdJournal.id).all()


def add_router_vrf(session, router_id):
    with session.begin(subtransactions=True):
        # Get the highest VRF number in the DB
        new_vrf = session.query(
            func.max(models.VppRouterVrf.vrf_id)).scalar() or 0
        new_vrf += 1

        row = models.VppRouterVrf(router_id=router_id, vrf_id=new_vrf)
        session.add(row)

    return new_vrf


def get_router_vrf(session, router_id):
    row = session.query(
        models.VppRouterVrf).filter_by(router_id=router_id).one()
    if row:
        return row.vrf_id

    return None


def delete_router_vrf(session, router_id):
    with session.begin(subtransactions=True):
        try:
            row = session.query(
                models.VppRouterVrf).filter_by(router_id=router_id).one()
            session.delete(row)
            session.flush()
        except Exception:
            pass
