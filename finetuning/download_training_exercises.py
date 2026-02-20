#!/usr/bin/env python3
"""Download Malware-Traffic-Analysis.net training exercises (pages + PCAP zips).

This pulls the index at:
  https://www.malware-traffic-analysis.net/training-exercises.html
and downloads each linked exercise/answer page HTML plus linked PCAP/ZIP assets.

Some exercises publish answer keys on a linked page (often page2.html / index2.html)
and those pages may link to answer-key ZIPs (e.g. answers.pdf.zip). Use
--download-linked-answer-assets to also fetch those.

WARNING: These artifacts may contain malware-related traffic. Handle safely.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

INDEX_URL = "https://www.malware-traffic-analysis.net/training-exercises.html"

ATTACH_EXTS = (".pcap", ".pcapng", ".pcap.zip", ".zip", ".7z")

# Linked pages often have answer-key bundles like *answers.pdf.zip or *answers.txt.zip.
# We only download these from linked pages when they look like answer keys.
ANSWER_KEYWORDS = ("answer", "answers", "solution", "key", "write-up", "writeup")
ANSWER_ASSET_EXTS = (".zip", ".7z", ".pdf", ".txt", ".log")


@dataclass(frozen=True)
class Item:
    url: str
    title: str
    year: int | None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _slug(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^a-z0-9._-]+", "", s)
    return s[:120] or "item"


def _extract_year(s: str) -> int | None:
    m = re.search(r"(20[0-9]{2})", s)
    return int(m.group(1)) if m else None


def _fetch_text(session: requests.Session, url: str, timeout: int) -> str:
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    r.encoding = r.encoding or "utf-8"
    return r.text


def _download_file(session: requests.Session, url: str, out_path: Path, timeout: int) -> None:
    if out_path.exists() and out_path.stat().st_size > 0:
        return
    r = session.get(url, timeout=timeout, stream=True)
    r.raise_for_status()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)


def _iter_index_items(index_html: str, base_url: str, min_year: int) -> list[Item]:
    """Parse the index page.

    The page uses <li> entries like:
      2025-06-13 -- Traffic analysis exercise: ...
    with two <a> tags per line (date + title). We parse the <li> text.
    """
    soup = BeautifulSoup(index_html, "html.parser")
    items: list[Item] = []
    for li in soup.find_all("li"):
        title = " ".join(li.get_text(" ", strip=True).split())
        if not title:
            continue
        if "--" not in title:
            continue
        if title.lower().startswith("click here"):
            continue

        a = li.find("a", href=True)
        if not a:
            continue
        url = urljoin(base_url, a["href"])
        year = _extract_year(title) or _extract_year(url)
        if year is None or year < min_year:
            continue
        items.append(Item(url=url, title=title, year=year))
    # De-dup
    seen = set()
    out: list[Item] = []
    for it in items:
        if it.url in seen:
            continue
        seen.add(it.url)
        out.append(it)
    return out


def _extract_assets(
    page_html: str,
    page_url: str,
    *,
    exts: tuple[str, ...] = ATTACH_EXTS,
    keywords: tuple[str, ...] = (),
) -> list[str]:
    soup = BeautifulSoup(page_html, "html.parser")
    links: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = urljoin(page_url, href)
        low = full.lower()
        if not any(low.endswith(ext) for ext in exts):
            continue
        if keywords:
            txt = (a.get_text(" ", strip=True) or "").lower()
            if not (any(k in low for k in keywords) or any(k in txt for k in keywords)):
                continue
        links.append(full)
    # De-dup
    dedup = []
    seen = set()
    for u in links:
        if u not in seen:
            seen.add(u)
            dedup.append(u)
    return dedup


def _extract_linked_html_pages(page_html: str, page_url: str, max_pages: int) -> list[str]:
    """Extract linked HTML pages in the same directory as the exercise page.

    Many exercises/answer keys are stored as index2.html/index3.html in the same
    folder. We intentionally do NOT spider the whole site.
    """
    soup = BeautifulSoup(page_html, "html.parser")
    parsed = urlparse(page_url)
    base_dir = parsed.path.rsplit("/", 1)[0] + "/"
    prefix = f"{parsed.scheme}://{parsed.netloc}{base_dir}"

    urls: list[str] = []
    for a in soup.find_all("a", href=True):
        full = urljoin(page_url, a["href"])
        low = full.lower()
        if not (low.endswith(".html") or low.endswith(".htm")):
            continue
        if not full.startswith(prefix):
            continue
        if full == page_url:
            continue
        urls.append(full)

    dedup: list[str] = []
    seen = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        dedup.append(u)
        if len(dedup) >= max_pages:
            break
    return dedup


def _rewrite_manifest_from_metadata(out_dir: Path) -> None:
    """Rewrite manifest.jsonl from per-page metadata.json files.

    This makes the downloader idempotent and avoids duplicated manifest lines
    across multiple runs.
    """
    pages_dir = out_dir / "pages"
    meta_files = sorted(pages_dir.glob("*/metadata.json"))
    manifest_path = out_dir / "manifest.jsonl"

    with open(manifest_path, "w", encoding="utf-8") as f:
        for mp in meta_files:
            try:
                obj = json.loads(mp.read_text(encoding="utf-8"))
            except Exception:
                continue
            f.write(json.dumps(obj) + "\n")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--min-year", type=int, default=2014)
    p.add_argument("--sleep", type=float, default=1.0, help="seconds between requests")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--max-linked-pages", type=int, default=10)
    p.add_argument(
        "--download-linked-answer-assets",
        action="store_true",
        help=(
            "Also download likely answer-key assets referenced from linked_pages HTML "
            "(filtered by keywords like 'answer' and 'solution')."
        ),
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=(Path(__file__).resolve().parent / "data" / "raw" / "training_exercises"),
    )
    args = p.parse_args()

    out_dir: Path = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "AIPAM-Downloader/1.0 (internal training)"})

    print(f"Fetching index: {INDEX_URL}")
    index_html = _fetch_text(session, INDEX_URL, timeout=args.timeout)
    (out_dir / "index.html").write_text(index_html, encoding="utf-8")

    items = _iter_index_items(index_html, base_url=INDEX_URL, min_year=args.min_year)
    print(f"Found {len(items)} exercise links (>= {args.min_year}).")

    for i, it in enumerate(items, start=1):
        safe_name = _slug(it.title)
        page_dir = out_dir / "pages" / safe_name
        page_dir.mkdir(parents=True, exist_ok=True)

        print(f"[{i}/{len(items)}] {it.title} -> {it.url}")
        try:
            html = _fetch_text(session, it.url, timeout=args.timeout)
            (page_dir / "page.html").write_text(html, encoding="utf-8")

            linked_pages = []
            for linked_url in _extract_linked_html_pages(html, it.url, max_pages=args.max_linked_pages):
                name = Path(urlparse(linked_url).path).name or _slug(linked_url)
                out_path = page_dir / "linked_pages" / name
                if not out_path.exists():
                    linked_html = _fetch_text(session, linked_url, timeout=args.timeout)
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(linked_html, encoding="utf-8")
                linked_pages.append({"url": linked_url, "path": str(out_path.relative_to(out_dir))})
                time.sleep(args.sleep)

            asset_urls: list[str] = []
            asset_urls.extend(_extract_assets(html, it.url))

            # Some answer-key bundles are only linked from page2.html/index2.html.
            if args.download_linked_answer_assets and linked_pages:
                for lp in linked_pages:
                    try:
                        lp_url = lp.get("url")
                        lp_rel = lp.get("path")
                        if not lp_url or not lp_rel:
                            continue
                        lp_path = out_dir / lp_rel
                        if not lp_path.exists():
                            continue
                        lp_html = lp_path.read_text(encoding="utf-8", errors="ignore")
                        asset_urls.extend(
                            _extract_assets(
                                lp_html,
                                lp_url,
                                exts=ANSWER_ASSET_EXTS,
                                keywords=ANSWER_KEYWORDS,
                            )
                        )
                    except Exception:
                        continue

            # De-dup across page + linked pages (keep order).
            assets: list[str] = []
            seen = set()
            for u in asset_urls:
                if u in seen:
                    continue
                seen.add(u)
                assets.append(u)

            downloaded = []
            for asset_url in assets:
                name = Path(urlparse(asset_url).path).name or _slug(asset_url)
                out_path = page_dir / "assets" / name
                _download_file(session, asset_url, out_path, timeout=args.timeout)
                downloaded.append({"url": asset_url, "path": str(out_path.relative_to(out_dir)), "sha256": _sha256(out_path)})
                time.sleep(args.sleep)

            meta = {
                **asdict(it),
                "saved_dir": str(page_dir.relative_to(out_dir)),
                "linked_pages": linked_pages,
                "assets": downloaded,
            }
            (page_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        except Exception as e:
            print(f"  !! Failed: {e}")

        time.sleep(args.sleep)

    # Ensure manifest is clean and deterministic even after partial runs/retries.
    _rewrite_manifest_from_metadata(out_dir)

    print(f"Done. Output: {out_dir}")


if __name__ == "__main__":
    main()

