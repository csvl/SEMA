import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
"""node task not unique

Revision ID: 2aa59981b59d
Revises: 151400d38e03
Create Date: 2015-07-17 10:54:27.568346

"""

revision = "2aa59981b59d"
down_revision = "151400d38e03"
branch_labels = None
depends_on = None

from alembic import op

def upgrade():
    op.drop_index("ix_node_task", table_name="task")
    op.create_index("ix_node_task", "task", ["node_id", "task_id"])

def downgrade():
    op.drop_index("ix_node_task", table_name="task")
    op.create_index("ix_node_task", "task", ["node_id", "task_id"], unique=True)
