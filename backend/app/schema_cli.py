"""One-shot migration and startup verification commands."""
import argparse
import json
import os
from pathlib import Path

from backend.app.schema_bootstrap import (
    adopt_legacy_database,
    assert_schema_current,
    restore_database_backup,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("migrate", "verify", "restore"))
    parser.add_argument("--database", default=os.environ.get("AIPAM_DB_PATH", "/data/aipam.db"))
    parser.add_argument("--backup")
    parser.add_argument("--receipt")
    parser.add_argument("--commit", action="store_true", help="perform restore after successful validation")
    args = parser.parse_args()
    path = Path(args.database)
    if args.command == "migrate":
        print(json.dumps(adopt_legacy_database(path), sort_keys=True))
    elif args.command == "verify":
        assert_schema_current(path)
        print("schema current")
    else:
        if not args.backup or not args.receipt:
            parser.error("restore requires --backup and --receipt")
        result = restore_database_backup(path, args.backup, args.receipt, commit=args.commit)
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
