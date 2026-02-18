from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .models import HostFinding, JobResult


def jobresult_to_markdown(
    result: JobResult,
    findings: Optional[Sequence[Any]] = None,
    evidence: Optional[Sequence[Any]] = None,
) -> str:
    lines: List[str] = []
    lines.append("# AIPAM Analysis Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- **Job ID**: `{result.job_id}`")
    lines.append(f"- **Severity**: **{_safe_str(result.summary.severity, 'unknown').lower()}**")
    lines.append(f"- **Classification**: **{_safe_str(result.summary.classification, 'unclassified')}**")

    bzar = result.raw.get("bzar") if isinstance(result.raw, dict) else None
    bzar_techniques = set((bzar or {}).get("technique_ids", []) or [])
    bzar_notices = (bzar or {}).get("notices", []) or []

    bzar_status = "enabled" if bzar else "disabled"
    lines.append(f"- **BZAR_STATUS**: {bzar_status}")

    if result.summary.key_findings:
        lines.append("- **Key Findings**:")
        for f in result.summary.key_findings:
            lines.append(f"  - {f}")
    else:
        lines.append("- **Key Findings**: None")
    lines.append("")

    # Anomalies & Evidence (from LLM chunks)
    llm_raw = result.raw.get("llm_analysis_raw", {}) if isinstance(result.raw, dict) else {}
    chunks = llm_raw.get("chunks", []) if isinstance(llm_raw, dict) else []

    if chunks:
        lines.append("## Anomalies & Evidence")
        seen_anomalies: set[str] = set()
        for chunk in chunks:
            if isinstance(chunk, dict) and chunk.get("anomalies"):
                for a in chunk["anomalies"]:
                    desc = a.get("description", "Anomaly")
                    if desc in seen_anomalies:
                        continue
                    seen_anomalies.add(desc)
                    lines.append(f"### {desc}")
                    lines.append(f"- **Confidence**: {a.get('confidence')}")
                    lines.append(f"- **Reason**: {a.get('reason')}")
                    lines.append(f"- **Related Hosts**: {', '.join(a.get('related_hosts', []))}")
                    lines.append("")

    lines.append("## MITRE ATT&CK Techniques")
    if result.summary.mitre_techniques:
        for t in result.summary.mitre_techniques:
            tid = t.get("id", "")
            name = t.get("name", "")
            lines.append(f"- {tid} {name}".strip())
    else:
        lines.append("- None")
    lines.append("")

    findings_list = [_as_dict(f) for f in (findings or [])]
    evidence_list = [_as_dict(e) for e in (evidence or [])]
    evidence_by_finding = _group_evidence_by_finding(evidence_list)
    title_map = {str(f.get("id", "")): _safe_str(f.get("title", "Finding")) for f in findings_list}
    evidence_by_flow = _group_evidence_by_flow(evidence_list, title_map)

    lines.append("## Detailed Findings")
    if not findings_list:
        lines.append("- No findings available.")
    for f in _sort_findings(findings_list):
        fid = _safe_str(f.get("id", ""), "finding")
        title = _safe_str(f.get("title", "Finding"), "Finding")
        severity = _safe_str(f.get("severity", "unknown")).lower()
        confidence = _format_confidence(f.get("confidence"))
        classification = _safe_str(f.get("classification", "unclassified"))
        mitre_id = _safe_str(f.get("mitre_technique_id", ""))
        mitre_name = _safe_str(f.get("mitre_technique_name", ""))
        mitre_desc = _safe_str(f.get("mitre_description", ""))
        attack_stage = _safe_str(f.get("attack_chain_stage", ""))
        analyst_status = _safe_str(f.get("analyst_status", "unverified"))
        analyst_notes = _safe_str(f.get("analyst_notes", ""))
        description = _safe_str(f.get("description", ""))
        affected_hosts = f.get("affected_hosts") or {}

        lines.append(f"### [{severity}] {title}")
        lines.append(f"- **Finding ID**: `{fid}`")
        lines.append(f"- **Classification**: {classification}")
        lines.append(f"- **Confidence**: {confidence}")
        if mitre_id or mitre_name:
            lines.append(f"- **MITRE**: {mitre_id} {mitre_name}".strip())
        tactics = f.get("mitre_tactics") or []
        if tactics:
            lines.append(f"- **Tactics**: {', '.join(tactics)}")
        if mitre_desc:
            lines.append(f"- **MITRE Description**: {_truncate(mitre_desc, 400)}")
        if bzar_techniques:
            matched = "yes" if mitre_id in bzar_techniques else "no"
            lines.append(f"- **BZAR Validation**: {matched}")
        if attack_stage:
            lines.append(f"- **Attack Chain Stage**: {attack_stage}")
        if affected_hosts:
            host_items = ", ".join(affected_hosts.keys()) if isinstance(affected_hosts, dict) else ", ".join(affected_hosts)
            lines.append(f"- **Affected Hosts**: {host_items}")
        lines.append(f"- **Analyst Status**: {analyst_status}")
        if analyst_notes:
            lines.append(f"- **Analyst Notes**: {analyst_notes}")
        if description:
            lines.append("")
            lines.append(description)
            lines.append("")

        ev_rows = evidence_by_finding.get(fid, [])
        if ev_rows:
            lines.append("**Evidence (Citations)**")
            for ev in ev_rows:
                flow_id = _safe_str(ev.get("flow_id", ""))
                snippet = _safe_str(ev.get("snippet", ""))
                snippet = _truncate(snippet, 240)
                if flow_id:
                    anchor = _anchor_id(flow_id)
                    lines.append(f"- [Flow `{flow_id}`](#flow-{anchor}): {snippet}")
                else:
                    lines.append(f"- {snippet}")
        lines.append("")

    lines.append("## Host Findings")
    for host in result.hosts:
        lines.append(f"### {host.ip} ({host.role})")
        for finding in host.findings:
            lines.append(f"- {finding}")
        lines.append("")

    if bzar_techniques:
        lines.append("## BZAR Secondary Validation")
        lines.append(f"- **Techniques Detected**: {', '.join(sorted(bzar_techniques))}")
        lines.append(f"- **Notices**: {len(bzar_notices)}")
        lines.append("")

    if evidence_by_flow:
        lines.append("## Evidence Index (Flows)")
        for flow_id, items in evidence_by_flow.items():
            anchor = _anchor_id(flow_id)
            lines.append(f'<a id="flow-{anchor}"></a>')
            lines.append(f"### Flow {flow_id}")
            for item in items:
                ref = _safe_str(item.get("finding_title", "Finding"))
                snippet = _truncate(_safe_str(item.get("snippet", "")), 300)
                lines.append(f"- {ref}: {snippet}")
            lines.append("")

    return "\n".join(lines)


def jobresult_to_html(
    result: JobResult,
    findings: Optional[Sequence[Any]] = None,
    evidence: Optional[Sequence[Any]] = None,
) -> str:
    """Generate a styled HTML report from the JobResult."""
    bzar = result.raw.get("bzar") if isinstance(result.raw, dict) else None
    bzar_techniques = set((bzar or {}).get("technique_ids", []) or [])
    bzar_notices = (bzar or {}).get("notices", []) or []

    findings_list = [_as_dict(f) for f in (findings or [])]
    evidence_list = [_as_dict(e) for e in (evidence or [])]
    evidence_by_finding = _group_evidence_by_finding(evidence_list)
    title_map = {str(f.get("id", "")): _safe_str(f.get("title", "Finding")) for f in findings_list}
    evidence_by_flow = _group_evidence_by_flow(evidence_list, title_map)

    # Build key findings HTML
    key_findings_html = ""
    for f in result.summary.key_findings:
        key_findings_html += f'<li>{_escape_html(f)}</li>\n'
    if not key_findings_html:
        key_findings_html = '<li class="empty">No key findings identified.</li>'

    # Build MITRE techniques HTML
    mitre_html = ""
    for t in result.summary.mitre_techniques:
        tid = t.get("id", "")
        name = t.get("name", "")
        mitre_html += f'<span class="mitre-tag">{_escape_html(tid)}</span> {_escape_html(name)}<br>\n'
    if not mitre_html:
        mitre_html = '<span class="empty">No MITRE techniques identified.</span>'

    # Build findings HTML
    findings_html = ""
    if not findings_list:
        findings_html = '<div class="empty">No findings available.</div>'
    for f in _sort_findings(findings_list):
        fid = _safe_str(f.get("id", ""))
        title = _safe_str(f.get("title", "Finding"))
        severity = _safe_str(f.get("severity", "unknown")).lower()
        confidence = _format_confidence(f.get("confidence"))
        classification = _safe_str(f.get("classification", "unclassified"))
        mitre_id = _safe_str(f.get("mitre_technique_id", ""))
        mitre_name = _safe_str(f.get("mitre_technique_name", ""))
        mitre_desc = _safe_str(f.get("mitre_description", ""))
        attack_stage = _safe_str(f.get("attack_chain_stage", ""))
        analyst_status = _safe_str(f.get("analyst_status", "unverified"))
        analyst_notes = _safe_str(f.get("analyst_notes", ""))
        description = _safe_str(f.get("description", ""))
        affected_hosts = f.get("affected_hosts") or {}
        tactics = f.get("mitre_tactics") or []
        host_items = ", ".join(affected_hosts.keys()) if isinstance(affected_hosts, dict) else ", ".join(affected_hosts) if affected_hosts else ""

        evidence_html = ""
        bzar_html = ""
        if bzar_techniques:
            matched = "yes" if mitre_id in bzar_techniques else "no"
            bzar_html = f'<span><strong>BZAR Validation:</strong> {matched}</span>'
        ev_rows = evidence_by_finding.get(fid, [])
        if ev_rows:
            ev_items = []
            for ev in ev_rows:
                flow_id = _safe_str(ev.get("flow_id", ""))
                snippet = _truncate(_safe_str(ev.get("snippet", "")), 240)
                if flow_id:
                    anchor = _anchor_id(flow_id)
                    ev_items.append(
                        f'<li><a href="#flow-{_escape_html(anchor)}">Flow {_escape_html(flow_id)}</a>: '
                        f'{_escape_html(snippet)}</li>'
                    )
                else:
                    ev_items.append(f'<li>{_escape_html(snippet)}</li>')
            evidence_html = f"<ul class=\"evidence-list\">{''.join(ev_items)}</ul>"
        else:
            evidence_html = '<div class="empty">No evidence records.</div>'

        findings_html += f'''
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-title">{_escape_html(title)}</div>
                <div class="finding-severity severity-{_escape_html(severity)}">{_escape_html(severity)}</div>
            </div>
            <div class="finding-meta">
                <span><strong>ID:</strong> {_escape_html(fid)}</span>
                <span><strong>Classification:</strong> {_escape_html(classification)}</span>
                <span><strong>Confidence:</strong> {_escape_html(confidence)}</span>
            </div>
            <div class="finding-meta">
                <span><strong>MITRE:</strong> {_escape_html(mitre_id)} {_escape_html(mitre_name)}</span>
                <span><strong>Attack Stage:</strong> {_escape_html(attack_stage)}</span>
                <span><strong>Affected Hosts:</strong> {_escape_html(host_items)}</span>
            </div>
            {f'<div class="finding-meta">{bzar_html}</div>' if bzar_html else ''}
            {f'<div class="finding-meta"><span><strong>Tactics:</strong> {_escape_html(", ".join(tactics))}</span></div>' if tactics else ''}
            <div class="finding-meta">
                <span><strong>Analyst Status:</strong> {_escape_html(analyst_status)}</span>
                <span><strong>Analyst Notes:</strong> {_escape_html(analyst_notes)}</span>
            </div>
            <div class="finding-desc">{_escape_html(description)}</div>
            {f'<div class="finding-desc"><strong>MITRE Description:</strong> {_escape_html(_truncate(mitre_desc, 400))}</div>' if mitre_desc else ''}
            <div class="finding-evidence">
                <h4>Evidence (Citations)</h4>
                {evidence_html}
            </div>
        </div>
        '''

    # Build evidence index HTML
    evidence_index_html = ""
    if evidence_by_flow:
        for flow_id, items in evidence_by_flow.items():
            item_lines = ""
            for item in items:
                ref = _safe_str(item.get("finding_title", "Finding"))
                snippet = _truncate(_safe_str(item.get("snippet", "")), 300)
                item_lines += f"<li>{_escape_html(ref)}: {_escape_html(snippet)}</li>"
            evidence_index_html += f'''
            <div class="evidence-card" id="flow-{_escape_html(_anchor_id(flow_id))}">
                <div class="evidence-header">Flow {_escape_html(flow_id)}</div>
                <ul class="evidence-list">{item_lines}</ul>
            </div>
            '''
    else:
        evidence_index_html = '<div class="empty">No evidence records.</div>'

    # Build host findings HTML
    hosts_html = ""
    for host in result.hosts:
        host_findings_list = ""
        for finding in host.findings:
            host_findings_list += f'<li>{_escape_html(finding)}</li>\n'
        if not host_findings_list:
            host_findings_list = '<li class="empty">No findings for this host.</li>'

        role_class = "role-attacker" if host.role == "attacker" else "role-victim" if host.role == "victim" else "role-unknown"
        hosts_html += f'''
        <div class="host-card">
            <div class="host-header">
                <span class="host-ip">{_escape_html(host.ip)}</span>
                <span class="host-role {role_class}">{_escape_html(host.role)}</span>
            </div>
            <ul class="host-findings">{host_findings_list}</ul>
        </div>
        '''
    if not hosts_html:
        hosts_html = '<div class="empty">No host findings available.</div>'

    # Severity styling
    severity = result.summary.severity.lower()
    severity_class = f"severity-{severity}"

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIPAM Report - {_escape_html(result.job_id)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            line-height: 1.6;
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{
            font-size: 1.75rem;
            font-weight: 600;
            color: #f1f5f9;
            margin-bottom: 0.5rem;
            border-bottom: 2px solid #334155;
            padding-bottom: 1rem;
        }}
        .job-id {{
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.875rem;
            color: #64748b;
            margin-bottom: 1.5rem;
        }}
        .section {{ margin-bottom: 2rem; }}
        .section-title {{
            font-size: 1.125rem;
            font-weight: 600;
            color: #34d399;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .section-title::before {{
            content: '';
            width: 4px;
            height: 1.25rem;
            background: #34d399;
            border-radius: 2px;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 0.5rem 1.25rem;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 1.5rem;
        }}
        .severity-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .severity-high {{ background: #7c2d12; color: #fdba74; }}
        .severity-medium {{ background: #78350f; color: #fcd34d; }}
        .severity-low {{ background: #14532d; color: #86efac; }}
        .severity-info {{ background: #1e3a5f; color: #93c5fd; }}
        ul {{ list-style: none; }}
        .findings-list li {{
            padding: 0.75rem 1rem;
            background: #1e293b;
            border-left: 3px solid #3b82f6;
            margin-bottom: 0.5rem;
            border-radius: 0 0.375rem 0.375rem 0;
        }}
        .mitre-tag {{
            display: inline-block;
            background: #312e81;
            color: #a5b4fc;
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-family: monospace;
            font-size: 0.875rem;
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        }}
        .host-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 0.5rem;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }}
        .host-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid #334155;
        }}
        .host-ip {{
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 1.125rem;
            font-weight: 600;
            color: #f1f5f9;
        }}
        .host-role {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .role-attacker {{ background: #7f1d1d; color: #fca5a5; }}
        .role-victim {{ background: #78350f; color: #fcd34d; }}
        .role-unknown {{ background: #334155; color: #94a3b8; }}
        .host-findings li {{
            padding: 0.5rem 0;
            border-bottom: 1px solid #334155;
            color: #cbd5e1;
        }}
        .host-findings li:last-child {{ border-bottom: none; }}
        .empty {{ color: #64748b; font-style: italic; }}
        .finding-card {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        .finding-title {{
            font-weight: 600;
            color: #f8fafc;
        }}
        .finding-severity {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .finding-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            font-size: 0.875rem;
            color: #cbd5e1;
            margin-bottom: 0.5rem;
        }}
        .finding-desc {{
            margin: 0.75rem 0;
            color: #e2e8f0;
        }}
        .finding-evidence h4 {{
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            color: #a5b4fc;
        }}
        .evidence-list li {{
            padding: 0.4rem 0;
            border-bottom: 1px solid #334155;
            color: #cbd5e1;
        }}
        .evidence-list li:last-child {{ border-bottom: none; }}
        .evidence-card {{
            background: #0b1020;
            border: 1px solid #334155;
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .evidence-header {{
            font-family: 'Monaco', 'Consolas', monospace;
            margin-bottom: 0.5rem;
            color: #93c5fd;
        }}
        .footer {{
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid #334155;
            text-align: center;
            color: #64748b;
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AIPAM Analysis Report</h1>
        <div class="job-id">Job ID: {_escape_html(result.job_id)}</div>

        <div class="severity-badge {severity_class}">
            Severity: {_escape_html(result.summary.severity)}
        </div>
        <div class="severity-badge severity-info">
            Classification: {_escape_html(result.summary.classification)}
        </div>

        <div class="section">
            <h2 class="section-title">Key Findings</h2>
            <ul class="findings-list">{key_findings_html}</ul>
        </div>

        <div class="section">
            <h2 class="section-title">MITRE ATT&CK Techniques</h2>
            <div class="mitre-container">{mitre_html}</div>
        </div>

        <div class="section">
            <h2 class="section-title">Detailed Findings</h2>
            {findings_html}
        </div>

        <div class="section">
            <h2 class="section-title">Host Analysis</h2>
            {hosts_html}
        </div>

        <div class="section">
            <h2 class="section-title">Forensic Evidence & Anomalies</h2>
            <ul class="findings-list">
                {_generate_anomalies_html(result)}
            </ul>
        </div>

        <div class="section">
            <h2 class="section-title">BZAR Secondary Validation</h2>
            <div class="mitre-container">
                {'<span class="empty">No BZAR techniques detected.</span>' if not bzar_techniques else ''}
                {'<br>'.join([f'<span class="mitre-tag">{_escape_html(t)}</span>' for t in sorted(bzar_techniques)])}
                {f'<div style="margin-top:0.5rem;color:#94a3b8;">Notices: {len(bzar_notices)}</div>' if bzar_techniques else ''}
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Evidence Index (Flows)</h2>
            {evidence_index_html}
        </div>

        <div class="footer">
            Generated by AIPAM (AI-Powered PCAP Analysis Module)
        </div>
    </div>
</body>
</html>'''


def _generate_anomalies_html(result: JobResult) -> str:
    """Generate HTML for anomalies and evidence."""
    html = ""
    llm_raw = result.raw.get("llm_analysis_raw", {}) if isinstance(result.raw, dict) else {}
    chunks = llm_raw.get("chunks", []) if isinstance(llm_raw, dict) else []

    if not chunks:
        return '<li class="empty">No detailed evidence available.</li>'

    seen_anomalies: set[str] = set()
    for chunk in chunks:
        if isinstance(chunk, dict) and chunk.get("anomalies"):
            for a in chunk["anomalies"]:
                desc = a.get("description", "Anomaly")
                if desc in seen_anomalies:
                    continue
                seen_anomalies.add(desc)

                html += f'''
                <li style="margin-bottom: 1rem;">
                    <strong>{_escape_html(desc)}</strong><br>
                    <span style="font-size: 0.875rem; color: #94a3b8;">
                        Confidence: {a.get('confidence')} | Reason: {_escape_html(a.get('reason'))}
                    </span>
                </li>
                '''
    return html or '<li class="empty">No detailed evidence available.</li>'


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _anchor_id(value: str) -> str:
    safe = []
    for ch in str(value):
        if ch.isalnum() or ch in {"-", "_"}:
            safe.append(ch)
        else:
            safe.append("-")
    return "".join(safe)


def _as_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return dict(obj)


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _format_confidence(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except Exception:
        return "n/a"


def _truncate(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "\u2026"


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: order.get(str(f.get("severity", "info")).lower(), 5))


def _group_evidence_by_finding(evidence: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for ev in evidence:
        fid = _safe_str(ev.get("finding_id", ""))
        if not fid:
            continue
        grouped.setdefault(fid, []).append(ev)
    return grouped


def _group_evidence_by_flow(
    evidence: List[Dict[str, Any]],
    finding_titles: Optional[Dict[str, str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for ev in evidence:
        flow_id = _safe_str(ev.get("flow_id", ""))
        if not flow_id:
            continue
        if finding_titles is not None:
            fid = _safe_str(ev.get("finding_id", ""))
            if fid and "finding_title" not in ev:
                ev["finding_title"] = finding_titles.get(fid, "Finding")
        grouped.setdefault(flow_id, []).append(ev)
    return grouped
