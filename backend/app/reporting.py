from __future__ import annotations

from typing import List

from .models import HostFinding, JobResult


def jobresult_to_markdown(result: JobResult) -> str:
    lines: List[str] = []
    lines.append(f"# AIPAM Analysis Report for Job {result.job_id}")
    lines.append("")
    lines.append(f"Overall severity: **{result.summary.severity}**")
    lines.append("## Key Findings")
    for f in result.summary.key_findings:
        lines.append(f"- {f}")
    lines.append("")
    lines.append("## MITRE ATT&CK Techniques")
    for t in result.summary.mitre_techniques:
        tid = t.get("id", "")
        name = t.get("name", "")
        lines.append(f"- {tid} {name}")
    lines.append("")
    lines.append("## Host Findings")
    for host in result.hosts:
        lines.append(f"### {host.ip} ({host.role})")
        for finding in host.findings:
            lines.append(f"- {finding}")
        lines.append("")
    return "\n".join(lines)


def jobresult_to_html(result: JobResult) -> str:
    """Generate a styled HTML report from the JobResult."""

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

    # Build host findings HTML
    hosts_html = ""
    for host in result.hosts:
        findings_list = ""
        for finding in host.findings:
            findings_list += f'<li>{_escape_html(finding)}</li>\n'
        if not findings_list:
            findings_list = '<li class="empty">No findings for this host.</li>'

        role_class = "role-attacker" if host.role == "attacker" else "role-victim" if host.role == "victim" else "role-unknown"
        hosts_html += f'''
        <div class="host-card">
            <div class="host-header">
                <span class="host-ip">{_escape_html(host.ip)}</span>
                <span class="host-role {role_class}">{_escape_html(host.role)}</span>
            </div>
            <ul class="host-findings">{findings_list}</ul>
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

        <div class="section">
            <h2 class="section-title">Key Findings</h2>
            <ul class="findings-list">{key_findings_html}</ul>
        </div>

        <div class="section">
            <h2 class="section-title">MITRE ATT&CK Techniques</h2>
            <div class="mitre-container">{mitre_html}</div>
        </div>

        <div class="section">
            <h2 class="section-title">Host Analysis</h2>
            {hosts_html}
        </div>

        <div class="footer">
            Generated by AIPAM (AI-Powered PCAP Analysis Module)
        </div>
    </div>
</body>
</html>'''


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

