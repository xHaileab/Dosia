"""Added files table.

Revision ID: 15bc2c528991
Revises: 2207474b6270
Create Date: 2024-04-24 06:12:12.865932

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '15bc2c528991'
down_revision = '2207474b6270'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('files',
    sa.Column('file_id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('file_name', sa.String(length=255), nullable=False),
    sa.Column('shelf_number', sa.String(length=50), nullable=True),
    sa.Column('scanner_user_id', sa.Integer(), nullable=True),
    sa.Column('date_created', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['scanner_user_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('file_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('files')
    # ### end Alembic commands ###
