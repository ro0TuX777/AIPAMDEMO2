#!/usr/bin/env python3
"""Extract non-PCAP forensic/answer-key artifacts from downloaded MTA exercise ZIPs.

Scans:
  finetuning/data/raw/training_exercises/pages/**/assets/*.zip

Extracts (by default) everything *except* PCAP/PCAPNG members into:
  .../<page>/assets_extracted/<zip_stem>/...

Produces a manifest similar to extracted_pcaps.jsonl:
  finetuning/data/raw/training_exercises/extracted_assets.jsonl

Notes:
- Uses common MTA ZIP password conventions (infected / infected_YYYYMMDD).
- Prevents path traversal by validating extracted paths remain under the output dir.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path


SKIP_SUFFIXES = (".pcap", ".pcapng")

# Repo root (…/AIPAM). Used to store manifest paths consistently as repo-relative.
REPO_ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def to_repo_rel(p: Path) -> str:
    """Return repo-relative path string when possible, otherwise absolute."""
    try:
        return str(p.resolve().relative_to(REPO_ROOT))
    except Exception:
        return str(p.resolve())


def guess_date_yyyymmdd(asset_path: Path) -> str | None:
    # Try filename
    m = re.search(r"(20[0-9]{2})-([01][0-9])-([0-3][0-9])", asset_path.name)
    if m:
        return f"{m.group(1)}{m.group(2)}{m.group(3)}"
    # Fall back: look at parent metadata.json ( .../<page>/assets/<file> )
    meta = asset_path.parents[1] / "metadata.json"
    if meta.exists():
        try:
            title = json.loads(meta.read_text(encoding="utf-8")).get("title", "")
            m2 = re.search(r"(20[0-9]{2})-([01][0-9])-([0-3][0-9])", title)
            if m2:
                return f"{m2.group(1)}{m2.group(2)}{m2.group(3)}"
        except Exception:
            pass
    return None


def iter_passwords(asset_path: Path) -> list[bytes | None]:
    yyyymmdd = guess_date_yyyymmdd(asset_path)
    pwds: list[bytes | None] = []
    if yyyymmdd:
        pwds.append(f"infected_{yyyymmdd}".encode())
    pwds.append(b"infected")
    pwds.append(None)  # try no password last

    out: list[bytes | None] = []
    seen: set[bytes | None] = set()
    for p in pwds:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def _safe_out_path(out_base: Path, member: str) -> Path:
    """Compute a safe extraction path for a zip member under out_base."""
    # Normalize separators and strip leading slashes
    member_norm = member.replace("\\", "/").lstrip("/")
    # Build output path and validate it stays under out_base
    out_path = (out_base / member_norm).resolve()
    out_base_resolved = out_base.resolve()
    if out_base_resolved == out_path or out_base_resolved in out_path.parents:
        return out_path
    raise ValueError(f"Unsafe zip member path: {member}")


def extract_assets(zip_path: Path, out_base: Path, overwrite: bool) -> list[dict]:
    """Extract non-PCAP members from zip_path into out_base."""
    out_base.mkdir(parents=True, exist_ok=True)
    extracted: list[dict] = []

    with zipfile.ZipFile(zip_path) as z:
        members = [n for n in z.namelist() if n and not n.endswith("/")]
        # Skip if zip contains only pcaps (common)
        wanted = [n for n in members if not n.lower().endswith(SKIP_SUFFIXES)]
        if not wanted:
            return extracted

        last_err: Exception | None = None
        for pwd in iter_passwords(zip_path):
            try:
                for name in wanted:
                    out_path = _safe_out_path(out_base, name)
                    out_path.parent.mkdir(parents=True, exist_ok=True)

                    already_present = out_path.exists() and not overwrite
                    if not already_present:
                        with z.open(name, pwd=pwd) as src, open(out_path, "wb") as dst:
                            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                                dst.write(chunk)

                    extracted.append(
                        {
                            "zip": to_repo_rel(zip_path),
                            "member": name,
                            "path": to_repo_rel(out_path),
                            "sha256": sha256(out_path),
                            "already_present": already_present,
                        }
                    )
                return extracted
            except Exception as e:
                last_err = e
                continue

        if last_err:
            raise last_err

    return extracted


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--root",
        type=Path,
        default=Path("finetuning/data/raw/training_exercises"),
        help="Root folder created by download_training_exercises.py",
    )
    ap.add_argument(
        "--out-subdir",
        default="assets_extracted",
        help="Subfolder under each exercise page dir to extract into",
    )
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument(
        "--append",
        action="store_true",
        help="Append to manifest instead of rewriting it",
    )
    args = ap.parse_args()

    root: Path = args.root
    assets = sorted(root.glob("pages/*/assets/*.zip"))
    print(f"Found {len(assets)} zip files under {root}.")

    manifest = root / "extracted_assets.jsonl"
    if not args.append:
        manifest.write_text("", encoding="utf-8")

    total = 0
    failed = 0

    for zp in assets:
        page_dir = zp.parents[1]
        out_base = page_dir / args.out_subdir / zp.stem
        try:
            extracted = extract_assets(zp, out_base, overwrite=args.overwrite)
            if extracted:
                with open(manifest, "a", encoding="utf-8") as f:
                    for rec in extracted:
                        f.write(json.dumps(rec) + "\n")
                total += len(extracted)
                print(f"Extracted {len(extracted)} files from {zp.name} -> {out_base}")
        except Exception as e:
            failed += 1
            print(f"!! Failed to extract {zp}: {e}")

    print(f"Done. Extracted {total} files (non-pcap) from {len(assets)} zips. Failed: {failed}.")
    print(f"Manifest: {manifest}")


if __name__ == "__main__":
    main()
