from __future__ import annotations

import argparse
from typing import Dict, List

from sqlmodel import Session

from ..database import engine, init_db
from .ingest import DEFAULT_SOURCES, ingest_domain


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest MITRE CTI bundles (manual update).")
    parser.add_argument(
        "--domains",
        nargs="+",
        default=["enterprise", "mobile", "ics"],
        help="Domains to ingest (enterprise, mobile, ics)",
    )
    parser.add_argument("--enterprise", help="Source URL or file for enterprise bundle")
    parser.add_argument("--mobile", help="Source URL or file for mobile bundle")
    parser.add_argument("--ics", help="Source URL or file for ics bundle")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    init_db()

    sources: Dict[str, str] = dict(DEFAULT_SOURCES)
    if args.enterprise:
        sources["enterprise"] = args.enterprise
    if args.mobile:
        sources["mobile"] = args.mobile
    if args.ics:
        sources["ics"] = args.ics

    domains: List[str] = []
    for d in args.domains:
        d = d.strip().lower()
        if d in {"enterprise", "mobile", "ics"}:
            domains.append(d)

    if not domains:
        raise SystemExit("No valid domains requested.")

    with Session(engine) as session:
        for domain in domains:
            result = ingest_domain(session, domain, sources[domain])
            print(
                f"[cti] {domain}: {result['count']} techniques "
                f"(version={result['bundle_version']}, sha={result['bundle_sha256'][:8]}...)"
            )


if __name__ == "__main__":
    main()
