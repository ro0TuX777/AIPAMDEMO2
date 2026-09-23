"""Converge the explicitly supported runtime metadata schema.

Declarations are frozen here, independent of future ORM changes. Existing
metadata-only tables must match the supported columns, keys and foreign keys;
only the named indexes and documented legacy columns may be added.
"""
from alembic import op
import sqlalchemy as sa

revision = "7f2c9a4e8b11"
down_revision = "7a4d8e2c9b10"
branch_labels = None
depends_on = None

SCHEMA = sa.MetaData()
# Foreign-key targets outside the adopted table set.
sa.Table("jobs", SCHEMA, sa.Column("job_id", sa.String(), primary_key=True))

sa.Table(
    "context_annotations",
    SCHEMA,
    sa.Column("id", sa.Integer(), nullable=False),
    sa.Column("job_id", sa.String(), nullable=False),
    sa.Column("annotation_id", sa.String(), nullable=False),
    sa.Column("host_ip", sa.String(), nullable=False),
    sa.Column("metric_name", sa.String(), nullable=False),
    sa.Column("metric_category", sa.String(), nullable=False),
    sa.Column("baseline_value", sa.Float(), nullable=True),
    sa.Column("observed_value", sa.Float(), nullable=True),
    sa.Column("deviation_factor", sa.Float(), nullable=True),
    sa.Column("population_size", sa.Integer(), nullable=True),
    sa.Column("severity", sa.String(), nullable=False),
    sa.Column("confidence", sa.Float(), nullable=False),
    sa.Column("title", sa.Text(), nullable=False),
    sa.Column("description", sa.Text(), nullable=False),
    sa.Column("why_unusual", sa.Text(), nullable=False),
    sa.Column("related_alert_ids_json", sa.Text(), nullable=True),
    sa.Column("related_finding_ids_json", sa.Text(), nullable=True),
    sa.Column("pcap_label", sa.String(), nullable=True),
    sa.Column("created_at", sa.String(), nullable=False),
    sa.PrimaryKeyConstraint(*["id"]),
    sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
    sa.UniqueConstraint(*["annotation_id"]),
)
sa.Index(
    "idx_annotations_host",
    *[SCHEMA.tables["context_annotations"].c[n] for n in ["job_id", "host_ip"]],
    unique=False,
)
sa.Index(
    "idx_annotations_job",
    *[SCHEMA.tables["context_annotations"].c[n] for n in ["job_id"]],
    unique=False,
)
sa.Index(
    "idx_annotations_metric",
    *[SCHEMA.tables["context_annotations"].c[n] for n in ["job_id", "metric_name"]],
    unique=False,
)
sa.Index(
    "idx_annotations_pcap_label",
    *[SCHEMA.tables["context_annotations"].c[n] for n in ["job_id", "pcap_label"]],
    unique=False,
)
sa.Index(
    "idx_annotations_severity",
    *[SCHEMA.tables["context_annotations"].c[n] for n in ["job_id", "severity"]],
    unique=False,
)

sa.Table(
    "incident_slices",
    SCHEMA,
    sa.Column("id", sa.Integer(), nullable=False),
    sa.Column("job_id", sa.String(), nullable=False),
    sa.Column("slice_id", sa.String(), nullable=False),
    sa.Column("label", sa.Text(), nullable=False),
    sa.Column("slice_type", sa.String(), nullable=False),
    sa.Column("severity", sa.String(), nullable=False),
    sa.Column("confidence", sa.Float(), nullable=False),
    sa.Column("community_ids_json", sa.Text(), nullable=True),
    sa.Column("host_ips_json", sa.Text(), nullable=True),
    sa.Column("time_start", sa.String(), nullable=True),
    sa.Column("time_end", sa.String(), nullable=True),
    sa.Column("alert_ids_json", sa.Text(), nullable=True),
    sa.Column("finding_ids_json", sa.Text(), nullable=True),
    sa.Column("ioc_ids_json", sa.Text(), nullable=True),
    sa.Column("connection_ids_json", sa.Text(), nullable=True),
    sa.Column("summary", sa.Text(), nullable=True),
    sa.Column("rank", sa.Integer(), nullable=False),
    sa.Column("pcap_label", sa.String(), nullable=True),
    sa.Column("created_at", sa.String(), nullable=False),
    sa.PrimaryKeyConstraint(*["id"]),
    sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
    sa.UniqueConstraint(*["slice_id"]),
)
sa.Index(
    "idx_slices_job",
    *[SCHEMA.tables["incident_slices"].c[n] for n in ["job_id"]],
    unique=False,
)
sa.Index(
    "idx_slices_pcap_label",
    *[SCHEMA.tables["incident_slices"].c[n] for n in ["job_id", "pcap_label"]],
    unique=False,
)
sa.Index(
    "idx_slices_rank",
    *[SCHEMA.tables["incident_slices"].c[n] for n in ["job_id", "rank"]],
    unique=False,
)
sa.Index(
    "idx_slices_severity",
    *[SCHEMA.tables["incident_slices"].c[n] for n in ["job_id", "severity"]],
    unique=False,
)

sa.Table(
    "job_log_sources",
    SCHEMA,
    sa.Column("id", sa.Integer(), nullable=False),
    sa.Column("job_id", sa.String(), nullable=False),
    sa.Column("upload_id", sa.String(), nullable=True),
    sa.Column("label", sa.String(), nullable=True),
    sa.Column("filename", sa.Text(), nullable=False),
    sa.Column("source_system", sa.String(), nullable=True),
    sa.Column("parser_hint", sa.String(), nullable=True),
    sa.Column("ordinal", sa.Integer(), nullable=False),
    sa.Column("size_bytes", sa.Integer(), nullable=True),
    sa.Column("sha256", sa.String(), nullable=True),
    sa.PrimaryKeyConstraint(*["id"]),
    sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
)
sa.Index(
    "idx_job_log_sources_job",
    *[SCHEMA.tables["job_log_sources"].c[n] for n in ["job_id"]],
    unique=False,
)
sa.Index(
    "idx_job_log_sources_ordinal",
    *[SCHEMA.tables["job_log_sources"].c[n] for n in ["job_id", "ordinal"]],
    unique=False,
)

sa.Table(
    "normalized_events",
    SCHEMA,
    sa.Column("id", sa.Integer(), nullable=False),
    sa.Column("event_id", sa.String(), nullable=False),
    sa.Column("job_id", sa.String(), nullable=False),
    sa.Column("event_type", sa.String(), nullable=False),
    sa.Column("timestamp", sa.String(), nullable=False),
    sa.Column("source_type", sa.String(), nullable=False),
    sa.Column("source_system", sa.String(), nullable=True),
    sa.Column("source_filename", sa.String(), nullable=True),
    sa.Column("parser_name", sa.String(), nullable=True),
    sa.Column("parser_version", sa.String(), nullable=True),
    sa.Column("raw_ref", sa.Text(), nullable=True),
    sa.Column("evidence_status", sa.String(), nullable=False),
    sa.Column("corroboration_score", sa.Float(), nullable=True),
    sa.Column("community_id", sa.String(), nullable=True),
    sa.Column("hostname", sa.String(), nullable=True),
    sa.Column("username", sa.String(), nullable=True),
    sa.Column("session_id", sa.String(), nullable=True),
    sa.Column("process_guid", sa.String(), nullable=True),
    sa.Column("src_ip", sa.String(), nullable=True),
    sa.Column("src_port", sa.Integer(), nullable=True),
    sa.Column("dest_ip", sa.String(), nullable=True),
    sa.Column("dest_port", sa.Integer(), nullable=True),
    sa.Column("proto", sa.String(), nullable=True),
    sa.Column("exercise_id", sa.String(), nullable=True),
    sa.Column("data_json", sa.Text(), nullable=True),
    sa.Column("correlation_keys_json", sa.Text(), nullable=True),
    sa.Column("tags_json", sa.Text(), nullable=True),
    sa.Column("pcap_label", sa.String(), nullable=True),
    sa.PrimaryKeyConstraint(*["id"]),
    sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
    sa.UniqueConstraint(*["event_id"]),
)
sa.Index(
    "idx_ne_community",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "community_id"]],
    unique=False,
)
sa.Index(
    "idx_ne_dest_ip",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "dest_ip"]],
    unique=False,
)
sa.Index(
    "idx_ne_evidence",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "evidence_status"]],
    unique=False,
)
sa.Index(
    "idx_ne_exercise",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["exercise_id"]],
    unique=False,
)
sa.Index(
    "idx_ne_hostname",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "hostname"]],
    unique=False,
)
sa.Index(
    "idx_ne_job_ts",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "timestamp"]],
    unique=False,
)
sa.Index(
    "idx_ne_job_type",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "event_type"]],
    unique=False,
)
sa.Index(
    "idx_ne_source_type",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "source_type"]],
    unique=False,
)
sa.Index(
    "idx_ne_src_ip",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "src_ip"]],
    unique=False,
)
sa.Index(
    "idx_ne_username",
    *[SCHEMA.tables["normalized_events"].c[n] for n in ["job_id", "username"]],
    unique=False,
)

sa.Table(
    "proofs",
    SCHEMA,
    sa.Column("id", sa.Integer(), nullable=False),
    sa.Column("job_id", sa.String(), nullable=False),
    sa.Column("proof_id", sa.String(), nullable=False),
    sa.Column("title", sa.Text(), nullable=False),
    sa.Column("conclusion", sa.Text(), nullable=True),
    sa.Column("status", sa.String(), nullable=False),
    sa.Column("severity", sa.String(), nullable=False),
    sa.Column("confidence", sa.Float(), nullable=False),
    sa.Column("mode", sa.String(), nullable=False),
    sa.Column("narrative_markdown", sa.Text(), nullable=True),
    sa.Column("item_count", sa.Integer(), nullable=False),
    sa.Column("created_at", sa.String(), nullable=False),
    sa.Column("updated_at", sa.String(), nullable=False),
    sa.PrimaryKeyConstraint(*["id"]),
    sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
    sa.UniqueConstraint(*["proof_id"]),
)
sa.Index(
    "idx_proofs_job", *[SCHEMA.tables["proofs"].c[n] for n in ["job_id"]], unique=False
)
sa.Index(
    "idx_proofs_status",
    *[SCHEMA.tables["proofs"].c[n] for n in ["job_id", "status"]],
    unique=False,
)

sa.Table(
    "reports",
    SCHEMA,
    sa.Column("id", sa.Integer(), nullable=False),
    sa.Column("job_id", sa.String(), nullable=False),
    sa.Column("report_id", sa.String(), nullable=False),
    sa.Column("mode", sa.String(), nullable=False),
    sa.Column("pcap_label", sa.String(), nullable=True),
    sa.Column("title", sa.Text(), nullable=False),
    sa.Column("threat_level", sa.String(), nullable=False),
    sa.Column("confidence", sa.Float(), nullable=False),
    sa.Column("content_markdown", sa.Text(), nullable=False),
    sa.Column("content_json", sa.Text(), nullable=False),
    sa.Column("theory_count", sa.Integer(), nullable=False),
    sa.Column("slice_count", sa.Integer(), nullable=False),
    sa.Column("finding_count", sa.Integer(), nullable=False),
    sa.Column("alert_count", sa.Integer(), nullable=False),
    sa.Column("ioc_count", sa.Integer(), nullable=False),
    sa.Column("host_count", sa.Integer(), nullable=False),
    sa.Column("annotation_count", sa.Integer(), nullable=False),
    sa.Column("evidence_refs_json", sa.Text(), nullable=True),
    sa.Column("created_at", sa.String(), nullable=False),
    sa.PrimaryKeyConstraint(*["id"]),
    sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
    sa.UniqueConstraint(*["report_id"]),
)
sa.Index(
    "idx_reports_job",
    *[SCHEMA.tables["reports"].c[n] for n in ["job_id"]],
    unique=False,
)
sa.Index(
    "idx_reports_mode",
    *[SCHEMA.tables["reports"].c[n] for n in ["job_id", "mode"]],
    unique=False,
)
sa.Index(
    "idx_reports_pcap_label",
    *[SCHEMA.tables["reports"].c[n] for n in ["job_id", "pcap_label"]],
    unique=False,
)

sa.Table(
    "theories",
    SCHEMA,
    sa.Column("id", sa.Integer(), nullable=False),
    sa.Column("job_id", sa.String(), nullable=False),
    sa.Column("theory_id", sa.String(), nullable=False),
    sa.Column("scope_type", sa.String(), nullable=False),
    sa.Column("scope_id", sa.String(), nullable=True),
    sa.Column("label", sa.Text(), nullable=False),
    sa.Column("hypothesis_type", sa.String(), nullable=False),
    sa.Column("score", sa.Float(), nullable=False),
    sa.Column("confidence", sa.String(), nullable=False),
    sa.Column("rank", sa.Integer(), nullable=False),
    sa.Column("supporting_evidence_json", sa.Text(), nullable=True),
    sa.Column("contradicting_evidence_json", sa.Text(), nullable=True),
    sa.Column("score_breakdown_json", sa.Text(), nullable=True),
    sa.Column("explanation", sa.Text(), nullable=True),
    sa.Column("next_steps_json", sa.Text(), nullable=True),
    sa.Column("pcap_label", sa.String(), nullable=True),
    sa.Column("created_at", sa.String(), nullable=False),
    sa.Column("analyst_status", sa.String(), nullable=True),
    sa.Column("analyst_notes", sa.Text(), nullable=True),
    sa.Column("reviewed_at", sa.String(), nullable=True),
    sa.Column("reviewer_id", sa.String(), nullable=True),
    sa.PrimaryKeyConstraint(*["id"]),
    sa.ForeignKeyConstraint(["job_id"], ["jobs.job_id"], ondelete="CASCADE"),
    sa.UniqueConstraint(*["theory_id"]),
)
sa.Index(
    "idx_theories_analyst_status",
    *[SCHEMA.tables["theories"].c[n] for n in ["job_id", "analyst_status"]],
    unique=False,
)
sa.Index(
    "idx_theories_job",
    *[SCHEMA.tables["theories"].c[n] for n in ["job_id"]],
    unique=False,
)
sa.Index(
    "idx_theories_pcap_label",
    *[SCHEMA.tables["theories"].c[n] for n in ["job_id", "pcap_label"]],
    unique=False,
)
sa.Index(
    "idx_theories_rank",
    *[
        SCHEMA.tables["theories"].c[n]
        for n in ["job_id", "scope_type", "scope_id", "rank"]
    ],
    unique=False,
)
sa.Index(
    "idx_theories_scope",
    *[SCHEMA.tables["theories"].c[n] for n in ["job_id", "scope_type", "scope_id"]],
    unique=False,
)

sa.Table(
    "proof_items",
    SCHEMA,
    sa.Column("id", sa.Integer(), nullable=False),
    sa.Column("proof_id", sa.String(), nullable=False),
    sa.Column("item_id", sa.String(), nullable=False),
    sa.Column("entity_type", sa.String(), nullable=False),
    sa.Column("entity_id", sa.String(), nullable=False),
    sa.Column("role", sa.String(), nullable=False),
    sa.Column("analyst_note", sa.Text(), nullable=True),
    sa.Column("order", sa.Integer(), nullable=False),
    sa.Column("label", sa.Text(), nullable=True),
    sa.Column("severity", sa.String(), nullable=True),
    sa.Column("created_at", sa.String(), nullable=False),
    sa.PrimaryKeyConstraint(*["id"]),
    sa.ForeignKeyConstraint(["proof_id"], ["proofs.proof_id"], ondelete="CASCADE"),
    sa.UniqueConstraint(*["item_id"]),
)
sa.Index(
    "idx_proof_items_entity",
    *[SCHEMA.tables["proof_items"].c[n] for n in ["entity_type", "entity_id"]],
    unique=False,
)
sa.Index(
    "idx_proof_items_proof",
    *[SCHEMA.tables["proof_items"].c[n] for n in ["proof_id"]],
    unique=False,
)

METADATA_TABLES = (
    "context_annotations",
    "incident_slices",
    "job_log_sources",
    "normalized_events",
    "proofs",
    "reports",
    "theories",
    "proof_items",
)

ADDITIONS = {
    "temporal_correlations": (
        sa.Column("log_source_filename", sa.String(), nullable=True),
        sa.Column("log_summary", sa.Text(), nullable=True),
    ),
    "alerts": (
        sa.Column("analyst_status", sa.String(), nullable=True),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.String(), nullable=True),
        sa.Column("reviewer_id", sa.String(), nullable=True),
    ),
    "files": (sa.Column("filename", sa.String(), nullable=True),),
    "findings": (
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("ts", sa.String(), nullable=True),
        sa.Column("src_ip", sa.String(), nullable=True),
        sa.Column("dest_ip", sa.String(), nullable=True),
        sa.Column(
            "evidence_status", sa.String(), nullable=False, server_default="observed"
        ),
        sa.Column(
            "corroboration_score", sa.Float(), nullable=False, server_default="0.0"
        ),
        sa.Column("corroborating_sources_json", sa.Text(), nullable=True),
        sa.Column("analyst_status", sa.String(), nullable=True),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.String(), nullable=True),
        sa.Column("reviewer_id", sa.String(), nullable=True),
    ),
    "jobs": (
        sa.Column("source_type", sa.String(), nullable=False),
        sa.Column("exercise_id", sa.String(), nullable=True),
        sa.Column("source_manifest_json", sa.Text(), nullable=True),
    ),
    "kb_documents": (sa.Column("content_sha256", sa.String(), nullable=True),),
}

INDEXES = {
    "alerts": {"idx_alerts_analyst_status": ("job_id", "analyst_status")},
    "findings": {
        "idx_findings_analyst_status": ("job_id", "analyst_status"),
        "idx_findings_evidence_status": ("job_id", "evidence_status"),
    },
    "kb_documents": {"idx_kb_doc_sha": ("content_sha256",)},
}

BACKFILLS = {
    ("jobs", "source_type"): "pcap",
    ("findings", "confidence"): 0.0,
    ("findings", "evidence_status"): "observed",
    ("findings", "corroboration_score"): 0.0,
}


def _ensure_indexes(name, expected):
    actual = {i["name"]: i for i in sa.inspect(op.get_bind()).get_indexes(name)}
    for index, columns in expected.items():
        if index not in actual:
            op.create_index(index, name, list(columns), unique=False)
        elif (
            tuple(actual[index]["column_names"]) != tuple(columns)
            or actual[index]["unique"]
        ):
            raise RuntimeError(f"Unsupported index shape: {name}.{index}")


def _validate_table(table):
    inspector = sa.inspect(op.get_bind())
    actual = {c["name"]: c for c in inspector.get_columns(table.name)}
    if set(actual) != set(table.c.keys()):
        raise RuntimeError(f"Unsupported columns: {table.name}")
    for col in table.c:
        found = actual[col.name]
        expected_default = str(col.server_default.arg) if col.server_default else None
        if found["default"] != expected_default:
            raise RuntimeError(f"Unsupported column default: {table.name}.{col.name}")
        if (
            found["type"]._type_affinity != col.type._type_affinity
            or found["nullable"] != col.nullable
        ):
            raise RuntimeError(f"Unsupported column shape: {table.name}.{col.name}")
    expected_indexes = {i.name for i in table.indexes}
    if any(
        i["name"] not in expected_indexes for i in inspector.get_indexes(table.name)
    ):
        raise RuntimeError(f"Unsupported indexes: {table.name}")
    if inspector.get_pk_constraint(table.name)["constrained_columns"] != [
        c.name for c in table.primary_key
    ]:
        raise RuntimeError(f"Unsupported primary key: {table.name}")
    uniques = {
        tuple(c["column_names"]) for c in inspector.get_unique_constraints(table.name)
    }
    expected = {
        tuple(c.name for c in constraint.columns)
        for constraint in table.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    }
    if uniques != expected:
        raise RuntimeError(f"Unsupported unique keys: {table.name}")
    foreign = {
        (
            tuple(f["constrained_columns"]),
            f["referred_table"],
            tuple(f["referred_columns"]),
            f["options"].get("ondelete"),
        )
        for f in inspector.get_foreign_keys(table.name)
    }
    expected_foreign = {
        (
            tuple(c.name for c in f.columns),
            f.referred_table.name,
            tuple(e.column.name for e in f.elements),
            f.ondelete,
        )
        for f in table.foreign_key_constraints
    }
    if foreign != expected_foreign:
        raise RuntimeError(f"Unsupported foreign keys: {table.name}")


def upgrade():
    bind = op.get_bind()
    for name in METADATA_TABLES:
        table = SCHEMA.tables[name]
        if not sa.inspect(bind).has_table(name):
            table.create(bind)
        else:
            _validate_table(table)
            _ensure_indexes(
                name, {i.name: tuple(c.name for c in i.columns) for i in table.indexes}
            )
    for name, columns in ADDITIONS.items():
        actual = {c["name"]: c for c in sa.inspect(bind).get_columns(name)}
        for column in columns:
            found = actual.get(column.name)
            if found is None:
                # Existing rows must be backfilled before imposing NOT NULL.
                op.add_column(
                    name,
                    sa.Column(
                        column.name,
                        column.type,
                        nullable=True,
                        server_default=column.server_default,
                    ),
                )
            elif found["type"]._type_affinity != column.type._type_affinity:
                raise RuntimeError(f"Unsupported column type: {name}.{column.name}")
            if not column.nullable:
                table = sa.table(name, sa.column(column.name))
                bind.execute(
                    table.update()
                    .where(table.c[column.name].is_(None))
                    .values({column.name: BACKFILLS[(name, column.name)]})
                )
            if found is None or found["nullable"] != column.nullable:
                with op.batch_alter_table(name) as batch:
                    batch.alter_column(
                        column.name, existing_type=column.type, nullable=column.nullable
                    )
        _ensure_indexes(name, INDEXES.get(name, {}))
    uniques = sa.inspect(bind).get_unique_constraints("hosts")
    keys = {tuple(c["column_names"]): c["name"] for c in uniques}
    if set(keys) == {("job_id", "ip")}:
        with op.batch_alter_table(
            "hosts", naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"}
        ) as batch:
            batch.drop_constraint(
                keys[("job_id", "ip")] or "uq_hosts_job_id", type_="unique"
            )
            batch.create_unique_constraint(
                "uq_hosts_job_id_ip_pcap_label", ["job_id", "ip", "pcap_label"]
            )
    elif set(keys) != {("job_id", "ip", "pcap_label")}:
        raise RuntimeError("Unsupported unique keys: hosts")


def downgrade():
    # These structures can predate Alembic. Preserve adopted tables and data;
    # rolling back runtime ownership is handled by the child revision.
    pass
