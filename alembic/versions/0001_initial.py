"""initial

Revision ID: 0001_initial
Revises: 
Create Date: 2026-04-29 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'claims',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('claim_id', postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column('text', sa.String(), nullable=False),
        sa.Column('claim_type', sa.String(length=50), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )

    op.create_table(
        'validation_results',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('validation_result_id', postgresql.UUID(as_uuid=True), nullable=True, unique=True),
        sa.Column('decision_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('rule_id', sa.String(length=100), nullable=True),
        sa.Column('rule_name', sa.String(length=255), nullable=True),
        sa.Column('passed', sa.Boolean(), nullable=True),
        sa.Column('evidence', sa.String(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )

    op.create_table(
        'decisions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('decision_id', postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column('alert_id', sa.String(length=255), nullable=True),
        sa.Column('llm_output', sa.String(), nullable=True),
        sa.Column('outcome', sa.String(length=20), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('component_scores', postgresql.JSONB(), nullable=True),
        sa.Column('correction_candidate', sa.String(), nullable=True),
        sa.Column('analyst_rationale', sa.String(), nullable=True),
        sa.Column('policy_profile_name', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
    )

    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('decision_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('record_data', postgresql.JSONB(), nullable=True),
        sa.Column('prev_hash', sa.String(length=64), nullable=False),
        sa.Column('curr_hash', sa.String(length=64), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )

    op.create_table(
        'analyst_overrides',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('override_id', postgresql.UUID(as_uuid=True), nullable=True, unique=True),
        sa.Column('decision_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('original_outcome', sa.String(length=20), nullable=True),
        sa.Column('new_outcome', sa.String(length=20), nullable=True),
        sa.Column('rationale', sa.String(), nullable=True),
        sa.Column('correction_suggestion', sa.String(), nullable=True),
        sa.Column('overridden_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('override_timestamp', sa.DateTime(), nullable=True),
        sa.Column('audit_hash', sa.String(length=64), nullable=True),
    )

    op.create_table(
        'policy_profiles',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('profile_id', postgresql.UUID(as_uuid=True), nullable=True, unique=True),
        sa.Column('name', sa.String(length=100), nullable=False, unique=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('thresholds', postgresql.JSONB(), nullable=True),
        sa.Column('rule_weights', postgresql.JSONB(), nullable=True),
        sa.Column('active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )

    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('username', sa.String(length=100), nullable=False, unique=True),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True),
        sa.Column('role', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_login', sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('users')
    op.drop_table('policy_profiles')
    op.drop_table('analyst_overrides')
    op.drop_table('audit_log')
    op.drop_table('decisions')
    op.drop_table('validation_results')
    op.drop_table('claims')
