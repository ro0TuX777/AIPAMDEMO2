from sqlalchemy import inspect

from backend.app import database_v2


def test_init_v2_db_adds_missing_explanation_feedback_column(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy-aipam.db"
    engine = database_v2.create_v2_engine(f"sqlite:///{db_path}")

    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id VARCHAR NOT NULL,
                finding_id VARCHAR NOT NULL,
                sensor VARCHAR NOT NULL,
                severity VARCHAR NOT NULL,
                category VARCHAR,
                title TEXT NOT NULL,
                summary TEXT,
                community_id VARCHAR,
                evidence_json TEXT,
                pcap_label VARCHAR,
                feedback VARCHAR
            )
            """
        )

    assert "explanation_feedback" not in {
        column["name"] for column in inspect(engine).get_columns("findings")
    }

    monkeypatch.setattr(database_v2, "_engine", engine)
    monkeypatch.setattr(database_v2, "_SessionLocal", None)

    database_v2.init_v2_db()

    assert "explanation_feedback" in {
        column["name"] for column in inspect(engine).get_columns("findings")
    }

    database_v2.reset_engine()