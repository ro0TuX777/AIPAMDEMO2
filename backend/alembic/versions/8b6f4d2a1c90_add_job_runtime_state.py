"""Persist runtime ownership, cancellation leases and accepted artifacts."""
from alembic import op
import sqlalchemy as sa

revision = "8b6f4d2a1c90"
down_revision = "7f2c9a4e8b11"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("jobs", sa.Column("celery_task_id", sa.String(), nullable=True))
    op.add_column(
        "jobs",
        sa.Column(
            "execution_attempt", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column("jobs", sa.Column("run_token", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("worker_id", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("worker_container_id", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("executor_pid", sa.Integer(), nullable=True))
    op.add_column(
        "jobs", sa.Column("executor_pid_start_ticks", sa.BigInteger(), nullable=True)
    )
    op.add_column("jobs", sa.Column("executor_boot_id", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("heartbeat_at", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("dispatched_at", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("cancel_requested_at", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("cancel_force_at", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("cancel_deadline_at", sa.String(), nullable=True))
    op.add_column(
        "jobs", sa.Column("cancel_escalation_token", sa.String(), nullable=True)
    )
    op.add_column(
        "jobs", sa.Column("cancel_escalation_started_at", sa.String(), nullable=True)
    )
    op.add_column(
        "jobs",
        sa.Column(
            "artifact_layout_version", sa.Integer(), nullable=False, server_default="1"
        ),
    )
    op.add_column(
        "jobs", sa.Column("accepted_run_manifest_json", sa.Text(), nullable=True)
    )
    op.create_index("idx_jobs_celery_task_id", "jobs", ["celery_task_id"], unique=False)
    with op.batch_alter_table("jobs") as batch:
        batch.alter_column(
            "artifact_layout_version", existing_type=sa.Integer(), server_default="2"
        )


def downgrade():
    op.drop_index("idx_jobs_celery_task_id", table_name="jobs")
    with op.batch_alter_table("jobs") as batch:
        batch.drop_column("accepted_run_manifest_json")
        batch.drop_column("artifact_layout_version")
        batch.drop_column("cancel_escalation_started_at")
        batch.drop_column("cancel_escalation_token")
        batch.drop_column("cancel_deadline_at")
        batch.drop_column("cancel_force_at")
        batch.drop_column("cancel_requested_at")
        batch.drop_column("dispatched_at")
        batch.drop_column("heartbeat_at")
        batch.drop_column("executor_boot_id")
        batch.drop_column("executor_pid_start_ticks")
        batch.drop_column("executor_pid")
        batch.drop_column("worker_container_id")
        batch.drop_column("worker_id")
        batch.drop_column("run_token")
        batch.drop_column("execution_attempt")
        batch.drop_column("celery_task_id")
