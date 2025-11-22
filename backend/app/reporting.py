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
    md = jobresult_to_markdown(result)
    # Extremely small v1: wrap markdown in <pre>. Can be upgraded to real markdown->HTML.
    return f"<html><body><pre>{md}</pre></body></html>"

