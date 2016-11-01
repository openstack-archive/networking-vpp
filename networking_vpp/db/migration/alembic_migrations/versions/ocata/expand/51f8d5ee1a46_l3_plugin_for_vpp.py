# Copyright 2017 Cisco Systems Inc.
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

"""L3 plugin for VPP

Revision ID: 51f8d5ee1a46
Revises: 6a909ba3748c
Create Date: 2016-10-17 16:39:11.037544

"""

# revision identifiers, used by Alembic.
revision = '51f8d5ee1a46'
down_revision = '6a909ba3748c'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('vpp_router_vrfs',
                    sa.Column('router_id', sa.String(36), primary_key=True),
                    sa.Column('vrf_id', sa.Integer, nullable=False))
