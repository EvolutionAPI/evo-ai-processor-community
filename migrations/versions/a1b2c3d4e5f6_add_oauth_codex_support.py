"""add OAuth Codex support

Revision ID: a1b2c3d4e5f6
Revises: 26a14ac7025d
Create Date: 2026-04-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '26a14ac7025d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add OAuth Codex columns to evo_core_api_keys table."""
    # Make the 'key' column nullable for OAuth-based keys
    op.alter_column(
        'evo_core_api_keys',
        'key',
        existing_type=sa.String(),
        nullable=True,
    )

    # Add auth_type column with default 'api_key'
    op.add_column(
        'evo_core_api_keys',
        sa.Column(
            'auth_type',
            sa.String(20),
            nullable=False,
            server_default='api_key',
        ),
    )

    # Add oauth_data column for encrypted OAuth token storage
    op.add_column(
        'evo_core_api_keys',
        sa.Column(
            'oauth_data',
            sa.Text(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Remove OAuth Codex columns from evo_core_api_keys table."""
    op.drop_column('evo_core_api_keys', 'oauth_data')
    op.drop_column('evo_core_api_keys', 'auth_type')

    # Restore the 'key' column to non-nullable
    op.alter_column(
        'evo_core_api_keys',
        'key',
        existing_type=sa.String(),
        nullable=False,
    )
