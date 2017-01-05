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

"""start networking-vpp expand branch

Revision ID: 87654321747070
Create Date: 2016-08-04 12:34:56.000000

"""

from neutron.db.migration import cli


# revision identifiers, used by Alembic.
revision = '87654321747070'
down_revision = '00656e76747070'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    pass
