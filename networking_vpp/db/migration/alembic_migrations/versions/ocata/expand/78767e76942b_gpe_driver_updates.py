# Copyright 2019 Cisco
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

"""gpe driver updates

Revision ID: 78767e76942b
Revises: 51f8d5ee1a46
Create Date: 2019-01-18 12:13:00.878034

"""

# revision identifiers, used by Alembic.
revision = '78767e76942b'
down_revision = '51f8d5ee1a46'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('vpp_gpe_allocations',
                    sa.Column('gpe_vni', sa.Integer, primary_key=True,
                              autoincrement=False),
                    sa.Column('allocated', sa.Boolean, nullable=False))
