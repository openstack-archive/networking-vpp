# Copyright (c) 2015 OpenStack Foundation
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

import sqlalchemy as sa

from neutron.db import model_base


class VppEtcdJournal(model_base.BASEV2):
    """Operations that have been committed to the DB but not implemented"""
    __tablename__ = 'vpp_etcd_journal'

    # NB(ijw): Note that the incremental nature of the autoincrement ID is used
    # to determine the time order of commits.
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True, nullable=False)
    k = sa.Column(sa.String(255), nullable=False)  # key in etcd to change
    v = sa.Column(sa.PickleType, nullable=True) # null == 'delete this key'

    # These are stats; they're not essential to operation.  Only retry_count
    # is ever updated directly.
    retry_count = sa.Column(sa.Integer, default=0, nullable=False)
    created_at = sa.Column(sa.DateTime, server_default=sa.func.now(), nullable=False)
    last_retried = sa.Column(sa.DateTime, server_default=sa.func.now(),
                             onupdate=sa.func.now(), nullable=False)
