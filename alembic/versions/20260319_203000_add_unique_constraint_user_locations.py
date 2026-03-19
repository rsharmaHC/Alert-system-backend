"""add partial unique index to user_locations (active only)

Revision ID: 20260319_203000
Revises: location_audience_v1
Create Date: 2026-03-19 20:30:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.exc import ProgrammingError


# revision identifiers, used by Alembic.
revision: str = '20260319_203000'
down_revision: Union[str, None] = 'location_audience_v1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Clean up any existing duplicate ACTIVE assignments first (keep oldest)
    try:
        op.execute("""
            DELETE FROM user_locations
            WHERE status = 'active'
            AND id NOT IN (
                SELECT min_id
                FROM (
                    SELECT MIN(id) as min_id
                    FROM user_locations
                    WHERE status = 'active'
                    GROUP BY user_id, location_id
                ) AS keep
            )
        """)
    except Exception as e:
        # Table might not exist yet or already clean
        pass
    
    # Drop old unique constraint if it exists (includes status in key)
    try:
        op.execute("""
            ALTER TABLE user_locations
            DROP CONSTRAINT IF EXISTS uq_user_location_active
        """)
    except Exception:
        pass
    
    # Create partial unique index (only for active status)
    # This prevents duplicate ACTIVE assignments but allows multiple inactive rows
    try:
        op.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_user_location_active
            ON user_locations (user_id, location_id)
            WHERE status = 'active'
        """)
    except ProgrammingError as e:
        # Index might already exist
        if 'already exists' not in str(e).lower():
            raise


def downgrade() -> None:
    # Remove the partial unique index
    try:
        op.execute("DROP INDEX IF EXISTS uq_user_location_active")
    except Exception:
        pass
