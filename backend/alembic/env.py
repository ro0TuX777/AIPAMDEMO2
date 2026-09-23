"""Alembic env.py for AIPAM V2 migrations.

Imports all V2 ORM models so autogenerate can detect schema changes.
Database URL is resolved from AIPAM_DB_PATH env var (falls back to alembic.ini).
"""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

from backend.app.database_v2 import Base
import backend.app.models  # noqa: F401

# Target metadata for autogenerate
target_metadata = Base.metadata

# Alembic Config object
config = context.config

# Set up Python logging from the config file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override sqlalchemy.url from env var if available
db_path = os.environ.get("AIPAM_DB_PATH")
configured_url = config.get_main_option("sqlalchemy.url")
if db_path and configured_url == "sqlite:///./aipam.db":
    config.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")

# Target metadata already defined above


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (SQL script generation)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # Required for SQLite ALTER TABLE support
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (direct DB connection)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=True,  # Required for SQLite ALTER TABLE support
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
