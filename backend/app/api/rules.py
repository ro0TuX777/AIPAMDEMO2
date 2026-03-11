"""
Suricata rule management endpoints.

Provides both file-level CRUD (list / read / write / delete .rules files)
and structured rule browsing (parse, search, filter, toggle enable/disable).
"""

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from backend.app.api.deps import verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.schemas.rules import (
    CategoryStats,
    ParsedRule,
    ParsedRuleListResponse,
    RuleFileStats,
    SuricataRuleItem,
    SuricataRuleUpdate,
    ToggleRulesRequest,
)
from backend.app.suricata_rules import ensure_suricata_rules_seeded

router = APIRouter(prefix="/rules/suricata", tags=["Rules"], dependencies=[Depends(verify_token)])

# ── Helpers ──────────────────────────────────────────────────────────────────

# Classtype → severity mapping (Suricata convention)
_CLASSTYPE_SEVERITY: Dict[str, int] = {
    "trojan-activity": 1, "exploit-kit": 1, "targeted-activity": 1,
    "command-and-control": 1, "domain-c2": 1, "credential-theft": 1,
    "shellcode-detect": 1, "attempted-admin": 1,
    "web-application-attack": 2, "attempted-user": 2, "social-engineering": 2,
    "misc-attack": 2, "attempted-recon": 2, "attempted-dos": 2,
    "bad-unknown": 2, "pup-activity": 2,
    "misc-activity": 3, "policy-violation": 3, "protocol-command-decode": 3,
    "web-application-activity": 3, "network-scan": 3, "not-suspicious": 3,
}

_RE_MSG = re.compile(r'msg\s*:\s*"([^"]*)"')
_RE_SID = re.compile(r'sid\s*:\s*(\d+)')
_RE_REV = re.compile(r'rev\s*:\s*(\d+)')
_RE_CLASSTYPE = re.compile(r'classtype\s*:\s*([^;]+)')
_RE_REFERENCE = re.compile(r'reference\s*:\s*([^;]+)')
_RE_HEADER = re.compile(
    r'^(#\s*)?(alert|drop|pass|reject)\s+'
    r'(\S+)\s+'       # protocol
    r'(\S+)\s+\S+\s+' # src + src_port
    r'->\s+'
    r'(\S+)\s+\S+\s+' # dst + dst_port
    r'\('
)


def _get_rule_path(settings: Settings, filename: str) -> Path:
    if not filename.endswith(".rules"):
        filename += ".rules"
    safe_name = os.path.basename(filename)
    return settings.aipam_suricata_rules_dir / safe_name


def _parse_line(line: str, line_number: int) -> Optional[ParsedRule]:
    """Parse a single Suricata rule line into a ParsedRule, or None."""
    stripped = line.strip()
    if not stripped:
        return None

    # Determine enabled/disabled
    enabled = True
    rule_text = stripped
    if stripped.startswith("#"):
        enabled = False
        rule_text = stripped.lstrip("# ")

    # Must look like a rule (starts with action keyword)
    hdr = _RE_HEADER.match(line.strip())
    if not hdr and not _RE_HEADER.match(rule_text):
        return None

    m_msg = _RE_MSG.search(rule_text)
    m_sid = _RE_SID.search(rule_text)
    if not m_sid:
        return None

    m_rev = _RE_REV.search(rule_text)
    m_ct = _RE_CLASSTYPE.search(rule_text)
    refs = _RE_REFERENCE.findall(rule_text)

    classtype = m_ct.group(1).strip() if m_ct else ""
    # Determine action from the rule text (not the commented line)
    action = "alert"
    for act in ("alert", "drop", "pass", "reject"):
        if rule_text.startswith(act):
            action = act
            break

    # Protocol / src / dst from header
    hdr2 = _RE_HEADER.match(rule_text)
    protocol = hdr2.group(3) if hdr2 else ""
    src = hdr2.group(4) if hdr2 else ""
    dst = hdr2.group(5) if hdr2 else ""

    return ParsedRule(
        sid=int(m_sid.group(1)),
        enabled=enabled,
        action=action,
        msg=m_msg.group(1) if m_msg else "",
        classtype=classtype,
        severity=_CLASSTYPE_SEVERITY.get(classtype, 3),
        protocol=protocol,
        src=src,
        dst=dst,
        rev=int(m_rev.group(1)) if m_rev else 1,
        references=[r.strip() for r in refs],
        raw=stripped,
        line_number=line_number,
    )


def _parse_file(path: Path) -> List[ParsedRule]:
    """Parse all rules from a .rules file."""
    rules: List[ParsedRule] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, start=1):
            parsed = _parse_line(line, i)
            if parsed:
                rules.append(parsed)
    return rules


# ── File-level endpoints (original) ─────────────────────────────────────────

@router.get("", response_model=List[SuricataRuleItem])
async def list_suricata_rules(settings: Settings = Depends(get_settings)):
    """List all Suricata rules files."""
    rules_dir = settings.aipam_suricata_rules_dir
    ensure_suricata_rules_seeded(rules_dir)

    results = []
    for f in sorted(rules_dir.glob("*.rules")):
        if f.is_file():
            stat = f.stat()
            results.append(SuricataRuleItem(
                filename=f.name,
                size_bytes=stat.st_size,
                updated_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            ))
    return results


@router.get("/{filename}/raw", response_model=SuricataRuleItem)
async def get_suricata_rule(filename: str, settings: Settings = Depends(get_settings)):
    """Read a specific Suricata rule file (raw content)."""
    path = _get_rule_path(settings, filename)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Rule file not found")

    stat = path.stat()
    return SuricataRuleItem(
        filename=path.name,
        content=path.read_text(encoding="utf-8"),
        size_bytes=stat.st_size,
        updated_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
    )


# Keep old GET /{filename} working (returns raw content)
@router.get("/{filename}", response_model=SuricataRuleItem)
async def get_suricata_rule_compat(filename: str, settings: Settings = Depends(get_settings)):
    """Read a specific Suricata rule file — backward-compatible."""
    # Don't match sub-paths like /{filename}/parsed
    if "/" in filename:
        raise HTTPException(status_code=404, detail="Not found")
    return await get_suricata_rule(filename, settings)


@router.put("/{filename}", response_model=SuricataRuleItem)
async def update_suricata_rule(
    filename: str, body: SuricataRuleUpdate, settings: Settings = Depends(get_settings),
):
    """Create or update a Suricata rule file."""
    path = _get_rule_path(settings, filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body.content, encoding="utf-8")

    stat = path.stat()
    return SuricataRuleItem(
        filename=path.name,
        content=body.content,
        size_bytes=stat.st_size,
        updated_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
    )


@router.delete("/{filename}", status_code=204)
async def delete_suricata_rule(filename: str, settings: Settings = Depends(get_settings)):
    """Delete a Suricata rule file."""
    path = _get_rule_path(settings, filename)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Rule file not found")
    path.unlink()
    return Response(status_code=204)


# ── Parsed / structured endpoints ───────────────────────────────────────────

@router.get("/{filename}/stats", response_model=RuleFileStats)
async def get_rule_file_stats(filename: str, settings: Settings = Depends(get_settings)):
    """Return aggregate stats for a rule file (category breakdown)."""
    path = _get_rule_path(settings, filename)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Rule file not found")

    rules = _parse_file(path)
    cats: Dict[str, Tuple[int, int]] = {}  # name -> (enabled, disabled)
    for r in rules:
        cat = r.classtype or "(uncategorized)"
        en, dis = cats.get(cat, (0, 0))
        if r.enabled:
            cats[cat] = (en + 1, dis)
        else:
            cats[cat] = (en, dis + 1)

    total_en = sum(1 for r in rules if r.enabled)
    return RuleFileStats(
        filename=filename,
        total_rules=len(rules),
        enabled=total_en,
        disabled=len(rules) - total_en,
        categories=sorted(
            [CategoryStats(name=k, total=v[0] + v[1], enabled=v[0], disabled=v[1]) for k, v in cats.items()],
            key=lambda c: c.total,
            reverse=True,
        ),
    )


@router.get("/{filename}/parsed", response_model=ParsedRuleListResponse)
async def get_parsed_rules(
    filename: str,
    search: Optional[str] = Query(None, description="Search in SID or msg"),
    category: Optional[str] = Query(None, description="Filter by classtype"),
    enabled: Optional[bool] = Query(None, description="Filter enabled/disabled"),
    severity: Optional[int] = Query(None, description="Filter by severity (1/2/3)"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    settings: Settings = Depends(get_settings),
):
    """Return parsed, searchable, paginated rules from a file."""
    path = _get_rule_path(settings, filename)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Rule file not found")

    all_rules = _parse_file(path)

    # Apply filters
    filtered = all_rules
    if search:
        q = search.lower()
        filtered = [
            r for r in filtered
            if q in r.msg.lower() or q in str(r.sid)
        ]
    if category is not None:
        filtered = [r for r in filtered if r.classtype == category]
    if enabled is not None:
        filtered = [r for r in filtered if r.enabled == enabled]
    if severity is not None:
        filtered = [r for r in filtered if r.severity == severity]

    total = len(filtered)
    total_en = sum(1 for r in filtered if r.enabled)
    page = filtered[offset: offset + limit]

    return ParsedRuleListResponse(
        items=page,
        total=total,
        total_enabled=total_en,
        total_disabled=total - total_en,
        offset=offset,
        limit=limit,
    )


@router.post("/{filename}/toggle")
async def toggle_rules(
    filename: str,
    body: ToggleRulesRequest,
    settings: Settings = Depends(get_settings),
):
    """Enable or disable rules by SID list or by category."""
    path = _get_rule_path(settings, filename)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Rule file not found")

    # Build set of target SIDs
    target_sids: set = set()
    if body.sids:
        target_sids = set(body.sids)

    # If toggling by category, parse to find matching SIDs
    if body.category:
        all_rules = _parse_file(path)
        for r in all_rules:
            if r.classtype == body.category:
                target_sids.add(r.sid)

    if not target_sids:
        raise HTTPException(status_code=400, detail="No matching rules found")

    # Read file, modify matching lines, write back
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    changed = 0
    for i, line in enumerate(lines):
        m_sid = _RE_SID.search(line)
        if not m_sid:
            continue
        sid = int(m_sid.group(1))
        if sid not in target_sids:
            continue

        stripped = line.lstrip()
        is_commented = stripped.startswith("#")

        if body.enabled and is_commented:
            # Enable: remove leading "# "
            lines[i] = stripped.lstrip("# ").lstrip()
            if not lines[i].endswith("\n"):
                lines[i] += "\n"
            changed += 1
        elif not body.enabled and not is_commented:
            # Disable: add "# " prefix
            lines[i] = "# " + stripped
            changed += 1

    path.write_text("".join(lines), encoding="utf-8")

    return {"changed": changed, "total_targeted": len(target_sids), "enabled": body.enabled}
