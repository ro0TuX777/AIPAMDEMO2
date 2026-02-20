#!/usr/bin/env python3
"""Extract PCAPs from downloaded MTA training exercise ZIPs.

Scans:
  finetuning/data/raw/training_exercises/pages/**/assets/*.zip
and extracts only *.pcap / *.pcapng into a sibling folder:
  .../pcaps/

ZIP password conventions often used by MTA:
  infected_YYYYMMDD  (from the exercise date)
  infected

This script is safe-by-default: it only extracts pcap/pcapng files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def guess_date_yyyymmdd(asset_path: Path) -> str | None:
    m = re.search(r"(20[0-9]{2})-([01][0-9])-([0-3][0-9])", asset_path.name)
    if m:
        return f"{m.group(1)}{m.group(2)}{m.group(3)}"
    # Fall back: look at parent metadata.json
    meta = asset_path.parents[1] / "metadata.json"  # .../<page>/assets/<file>
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
    # de-dup
    out: list[bytes | None] = []
    seen = set()
    for p in pwds:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def extract_pcaps(zip_path: Path, out_dir: Path, overwrite: bool) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[dict] = []

    with zipfile.ZipFile(zip_path) as z:
        members = [n for n in z.namelist() if n.lower().endswith((".pcap", ".pcapng"))]
        if not members:
            return extracted

        last_err: Exception | None = None
        for pwd in iter_passwords(zip_path):
            try:
                for name in members:
                    out_name = Path(name).name  # prevent path traversal
                    out_path = out_dir / out_name
                    if out_path.exists() and not overwrite:
                        continue
                    with z.open(name, pwd=pwd) as src, open(out_path, "wb") as dst:
                        for chunk in iter(lambda: src.read(1024 * 1024), b""):
                            dst.write(chunk)
                    extracted.append({"zip": str(zip_path), "member": name, "path": str(out_path), "sha256": sha256(out_path)})
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
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args()

    root: Path = args.root
    assets = sorted(root.glob("pages/*/assets/*.zip"))
    print(f"Found {len(assets)} zip files under {root}.")

    manifest = root / "extracted_pcaps.jsonl"
    total = 0

    for zp in assets:
        page_dir = zp.parents[1]
        out_dir = page_dir / "pcaps"
        try:
            extracted = extract_pcaps(zp, out_dir, overwrite=args.overwrite)
            if extracted:
                with open(manifest, "a", encoding="utf-8") as f:
                    for rec in extracted:
                        f.write(json.dumps(rec) + "\n")
                total += len(extracted)
                print(f"Extracted {len(extracted)} pcaps from {zp.name} -> {out_dir}")
        except Exception as e:
            print(f"!! Failed to extract {zp}: {e}")

    print(f"Done. Extracted {total} pcap/pcapng files.")


if __name__ == "__main__":
    main()

