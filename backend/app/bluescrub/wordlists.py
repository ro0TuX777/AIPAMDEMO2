"""Dirty-word lists — the operator-editable side of the Attribution pillar.

The vendored scanner ships three packs and a file-backed CRUD layer. The packs
are worth keeping; the storage is not — AIPAM has ``bluescrub_wordlists``, and
two sources of truth for the same data is how an air-gapped deployment ends up
scanning against a list nobody can find.

Regex entries are accepted by the schema and rejected on save. The matching
engine is literal-only, and shipping a half-supported ``kind`` field that
silently never matches would be worse than refusing it. See §3 for why the
usual ReDoS argument is not the blocker here.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §Dirty Word search
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.bluescrub import BlueScrubWordlist

logger = logging.getLogger(__name__)

MAX_TERM_LENGTH = 256
MAX_TERMS_PER_LIST = 5000

#: Category drives severity: a classification marking is not a build path.
TERM_CATEGORIES: frozenset[str] = frozenset({
    "marking",      # classification markings
    "identity",     # operator handles, author names
    "org",          # agency or unit names
    "codename",     # project or operation names
    "hostname",     # internal hosts and domains
    "ticket",       # tracker ids
    "path",         # build and PDB paths
    "mutex",        # unique mutex or pipe names
    "tooling",      # framework and tool signatures
    "toolchain",    # compiler and build-system identifiers
    "hygiene",      # developer-note markers, placeholders, generic accounts
})

_DEFAULT_CATEGORY = "codename"

#: Categories whose builtin terms are seeded switched **off**.
#:
#: Measured on a 414-file corpus, 2853 of 5866 findings — 49% — came from the
#: hygiene tier of the shipped packs. This scanner's whole premise is that the
#: operator declared what matters, and nobody declared `TODO`. The terms are
#: real and weak, so they are neither dropped nor forced on: they are seeded
#: into their own list, visible, one toggle from active.
OPT_IN_CATEGORIES: frozenset[str] = frozenset({"hygiene"})

#: Where the opt-in terms from every shipped pack are collected.
OPT_IN_LIST_NAME = "Developer Hygiene"


class WordlistError(ValueError):
    """Rejected wordlist input. ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ── validation ────────────────────────────────────────────────────────────

def validate_entries(entries: list[dict]) -> list[dict]:
    """Normalise and validate wordlist entries, or refuse them.

    Refusal beats silent correction: a term that was quietly dropped looks
    identical to a term that matched nothing.
    """
    if not isinstance(entries, list):
        raise WordlistError("entries_not_a_list")
    if len(entries) > MAX_TERMS_PER_LIST:
        raise WordlistError("too_many_terms", f"{len(entries)} > {MAX_TERMS_PER_LIST}")

    seen: set[str] = set()
    out: list[dict] = []

    for raw in entries:
        if isinstance(raw, str):
            raw = {"term": raw}
        if not isinstance(raw, dict):
            raise WordlistError("entry_not_an_object", str(raw)[:64])

        term = str(raw.get("term") or "").strip()
        if not term:
            raise WordlistError("empty_term")
        if len(term) > MAX_TERM_LENGTH:
            raise WordlistError("term_too_long", term[:48])

        kind = str(raw.get("kind") or "literal").lower()
        if kind == "regex":
            # The engine is literal-only. Accepting a regex entry that can
            # never match would present as coverage.
            raise WordlistError(
                "regex_not_supported",
                f"{term[:48]!r} — the matcher is literal-only; see wordlists.py",
            )
        if kind != "literal":
            raise WordlistError("unknown_kind", kind)

        category = str(raw.get("category") or _DEFAULT_CATEGORY).lower()
        if category not in TERM_CATEGORIES:
            raise WordlistError("unknown_category", category)

        # A two-character term matches everywhere. "C2" taught that lesson at
        # scale: it fired 67 times on a codebase that merely discusses C2.
        if len(term) < 3:
            raise WordlistError(
                "term_too_short",
                f"{term!r} — a term under three characters matches everywhere",
            )

        key = term.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append({"term": term, "kind": "literal", "category": category})

    if not out:
        raise WordlistError("no_usable_terms")
    return out


# ── CRUD ──────────────────────────────────────────────────────────────────

def create(db: Session, name: str, entries: list[dict], *,
           case_sensitive: bool = False, category: str | None = None) -> BlueScrubWordlist:
    row = BlueScrubWordlist(
        id=str(uuid.uuid4()), name=name.strip() or "untitled", builtin=False,
        category=category, entries_json=json.dumps(validate_entries(entries)),
        case_sensitive=case_sensitive, created_at=_now(),
    )
    db.add(row)
    db.commit()
    return row


def update(db: Session, list_id: str, **fields) -> BlueScrubWordlist:
    row = db.get(BlueScrubWordlist, list_id)
    if row is None:
        raise WordlistError("not_found", list_id)
    if row.builtin:
        raise WordlistError("builtin_is_read_only", row.name)

    if "entries" in fields:
        row.entries_json = json.dumps(validate_entries(fields["entries"]))
    if "name" in fields:
        row.name = str(fields["name"]).strip() or row.name
    if "case_sensitive" in fields:
        row.case_sensitive = bool(fields["case_sensitive"])
    row.updated_at = _now()
    db.commit()
    return row


def set_enabled(db: Session, list_id: str, enabled: bool) -> BlueScrubWordlist:
    """Turn a list on or off. Permitted on builtins, unlike ``update``.

    ``builtin`` means "these terms are not yours to edit". Whether a pack is
    hunted at all is a different question, and an operator who cannot answer it
    ends up either drowning in a pack they did not ask for or deleting terms
    they may want back.
    """
    row = db.get(BlueScrubWordlist, list_id)
    if row is None:
        raise WordlistError("not_found", list_id)
    row.enabled = bool(enabled)
    row.updated_at = _now()
    db.commit()
    return row


def delete(db: Session, list_id: str) -> None:
    row = db.get(BlueScrubWordlist, list_id)
    if row is None:
        raise WordlistError("not_found", list_id)
    if row.builtin:
        raise WordlistError("builtin_is_read_only", row.name)
    db.delete(row)
    db.commit()


def all_lists(db: Session) -> list[BlueScrubWordlist]:
    return list(db.scalars(select(BlueScrubWordlist).order_by(
        BlueScrubWordlist.builtin.desc(), BlueScrubWordlist.name)).all())


# ── builtin packs ─────────────────────────────────────────────────────────

#: Which category each vendored pack's terms carry. The packs are flat word
#: lists upstream; the category is what lets severity differ between a
#: classification marking and a build-path fragment.
_PACK_CATEGORY = {
    "Common Leaks": "identity",
    "Tool Signatures": "tooling",
    "Build Artifacts": "path",
}

#: Per-term overrides for the shipped packs.
#:
#: A pack-level category was not enough, and the gap was not cosmetic. "Common
#: Leaks (OPSEC)" is a mixed bag — personal email domains next to `TODO`,
#: `DEBUG`, `admin` and `password` — and one category for all of it put
#: developer-hygiene markers into the `identity` tier, which is the
#: disqualifying one. The effect: **any** source tree containing a TODO comment
#: scored F with `disqualified: true`, from the builtin packs alone, with no
#: operator input at all.
#:
#: This is the same failure the critical ceiling was written for — a term that
#: matches everywhere standing in for a term that means something — arriving
#: through the input side rather than the detector side. The three-character
#: floor does not catch it: `TODO` is four characters.
#:
#: Reviewed per term. Anything not listed keeps its pack's category.
_TERM_CATEGORY: dict[str, str] = {
    # Developer-note markers. Present in essentially every codebase.
    "todo": "hygiene", "fixme": "hygiene", "hack": "hygiene",
    "xxx": "hygiene", "debug": "hygiene",
    # Placeholder credentials. `fpfilter` already suppresses these as values;
    # as declared terms they would fire on every assignment that mentions one.
    "password": "hygiene", "changeme": "hygiene", "passw0rd": "hygiene",
    "secret": "hygiene",
    # Generic account names. A hardcoded `Administrator` may well be a finding,
    # but it is a default-credential finding, not an identity leak — and
    # `admin`, `root`, `user` and `test` appear in every tree there is.
    "administrator": "hygiene", "admin": "hygiene", "root": "hygiene",
    "user": "hygiene", "test": "hygiene", "jdoe": "hygiene",
    # Ubiquitous paths that precede nothing in particular. `C:\Users\` and
    # `/home/` are kept at `path` because a username follows them.
    "/tmp/": "hygiene", "c:\\windows\\temp": "hygiene",
    "localhost": "hygiene", ".local": "hygiene",
    # These two do precede a username, which is the leak — but the prefix on
    # its own appears in every path-handling routine ever written, so it is a
    # build-path finding and not an identity one.
    "/home/": "path", "c:\\users\\": "path",
    # Internal namespaces do name infrastructure.
    ".internal": "hostname", ".corp": "hostname", ".lab": "hostname",
    # Personal mail domains in offensive tooling are the end of deniability.
    "@gmail.com": "identity", "@outlook.com": "identity",
    "@yahoo.com": "identity", "@protonmail.com": "identity",
    # Build Artifacts: the compiler identifiers describe the build environment,
    # not its operator — the same split the build-path scanner draws.
    "gcc": "toolchain", "clang": "toolchain", "mingw": "toolchain",
    "msvc": "toolchain", "visual studio": "toolchain",
    "cmakelists": "toolchain", "makefile": "toolchain",
    "__file__": "toolchain", "__line__": "toolchain", "__function__": "toolchain",
    "build:": "toolchain", "version:": "toolchain", "compiled by": "toolchain",
}


def seed_builtins(db: Session) -> int:
    """Install the vendored packs as read-only lists. Idempotent."""
    from backend.app.bluescrub.vendored.dirty_word_scanner import _DEFAULT_PREBUILT

    installed = 0
    deferred: list[dict] = []
    for pack in _DEFAULT_PREBUILT:
        # Upstream decorates names with emoji; strip so lookups are stable.
        name = re.sub(r"^[^\w]+", "", str(pack.get("name") or "")).strip()
        if not name:
            continue
        existing = db.scalar(
            select(BlueScrubWordlist).where(BlueScrubWordlist.name == name)
        )
        if existing is not None:
            continue

        category = next(
            (v for k, v in _PACK_CATEGORY.items() if name.startswith(k)),
            _DEFAULT_CATEGORY,
        )
        terms = [
            {"term": w, "kind": "literal",
             "category": _TERM_CATEGORY.get(str(w).strip().casefold(), category)}
            for w in pack.get("words") or []
            if len(str(w).strip()) >= 3
        ]
        # The shipped packs are mixed. The opt-in tier is lifted out rather
        # than dropped: an operator who wants TODO markers hunted can have
        # them, and one who does not is not asked to delete anything.
        deferred.extend(t for t in terms if t["category"] in OPT_IN_CATEGORIES)
        terms = [t for t in terms if t["category"] not in OPT_IN_CATEGORIES]
        if not terms:
            continue

        db.add(BlueScrubWordlist(
            id=str(uuid.uuid4()), name=name, builtin=True, category=category,
            entries_json=json.dumps(terms), case_sensitive=False,
            enabled=True, created_at=_now(),
        ))
        installed += 1

    if deferred and db.scalar(
        select(BlueScrubWordlist).where(BlueScrubWordlist.name == OPT_IN_LIST_NAME)
    ) is None:
        db.add(BlueScrubWordlist(
            id=str(uuid.uuid4()), name=OPT_IN_LIST_NAME, builtin=True,
            category=sorted(OPT_IN_CATEGORIES)[0],
            entries_json=json.dumps(deferred), case_sensitive=False,
            # Off by default. This is the one pack nobody asked for.
            enabled=False, created_at=_now(),
        ))
        installed += 1

    if installed:
        db.commit()
        logger.info("seeded %d builtin dirty-word pack(s)", installed)
    return installed


def active_terms(db: Session) -> list[dict]:
    """Every term from every **enabled** list, deduplicated, with its category."""
    seen: set[str] = set()
    terms: list[dict] = []
    for row in all_lists(db):
        if not row.enabled:
            continue
        try:
            entries = json.loads(row.entries_json)
        except (TypeError, ValueError):
            logger.warning("wordlist %s has unreadable entries", row.id)
            continue
        for entry in entries:
            term = str(entry.get("term") or "")
            key = term if row.case_sensitive else term.casefold()
            if not term or key in seen:
                continue
            seen.add(key)
            terms.append({
                "term": term,
                "category": entry.get("category") or _DEFAULT_CATEGORY,
                "case_sensitive": bool(row.case_sensitive),
                "list": row.name,
            })
    return terms
