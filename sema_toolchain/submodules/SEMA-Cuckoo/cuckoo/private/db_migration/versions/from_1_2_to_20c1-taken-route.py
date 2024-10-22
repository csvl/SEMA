import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""taken route for a task (from Cuckoo 1.2 to 2.0-rc1)

Revision ID: 1070cd314621
Revises: 4a04f40d4ab4
Create Date: 2015-11-21 23:10:04.724813

"""

# revision identifiers, used by Alembic.
revision = "1070cd314621"
down_revision = "4a04f40d4ab4"

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column("tasks", sa.Column("route", sa.String(length=16), nullable=True))

def downgrade():
    pass
