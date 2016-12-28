# Copyright 2016 Cisco
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
#

"""Add VPP journal table for etcd transactions

Revision ID: 6a909ba3748c
Revises: 87654321747070
Create Date: 2016-08-04 19:56:53.880202

"""

# revision identifiers, used by Alembic.
revision = '6a909ba3748c'
down_revision = '87654321747070'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('vpp_etcd_journal',
                    sa.Column('id', sa.Integer, primary_key=True,
                              autoincrement=True, nullable=False),
                    sa.Column('k', sa.String(255), nullable=False),
                    sa.Column('v', sa.PickleType, nullable=True),
                    sa.Column('retry_count', sa.Integer, default=0),
                    sa.Column('created_at', sa.DateTime,
                              default=sa.func.now()),
                    sa.Column('last_retried', sa.TIMESTAMP,
                              server_default=sa.func.now(),
                              onupdate=sa.func.now()))
