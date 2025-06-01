"""add_original_name_to_file

Revision ID: 540cc2d05dd3
Revises: f7e3d9a0c5b1
Create Date: 2025-06-01 02:37:10.727421

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '540cc2d05dd3'
down_revision = 'f7e3d9a0c5b1'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add column as nullable first
    op.add_column('files', sa.Column('original_name', sa.String(length=100), nullable=True))
    
    # Step 2: Set default value for existing rows
    op.execute("UPDATE files SET original_name = filename")
    
    # Step 3: Alter column to NOT NULL
    with op.batch_alter_table('files', schema=None) as batch_op:
        batch_op.alter_column('original_name', nullable=False)


def downgrade():
    with op.batch_alter_table('files', schema=None) as batch_op:
        batch_op.drop_column('original_name')