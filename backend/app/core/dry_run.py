"""Dry-run: Zeek record → FlowDB → AnalysisContext → Finding.

Run with:
    python -m app.core.dry_run

Demonstrates the full data flow through the new forensic architecture
without requiring a running database, Zeek, or LLM.
"""

from __future__ import annotations



def main() -> None:
    """Execute the dry-run demonstrating the complete data flow."""

    print("=" * 70)
    print("AIPAM Phase 1b Dry Run — Evidence Store + Forensic Interface")
    print("=" * 70)

    # -----------------------------------------------------------------------
    # Step 1: Raw Zeek conn.log record
    # -----------------------------------------------------------------------

    raw_zeek_record = {
        "ts": 1700000000.0,
        "uid": "CdhXbc2WnVWrx1hLXl",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 49152,
        "id.resp_h": "185.70.40.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 120.5,
        "orig_bytes": 15000,
        "resp_bytes": 250000,
        "conn_state": "SF",
        "missed_bytes": 0,
        "history": "ShADadFf",
        "orig_pkts": 150,
        "orig_ip_bytes": 21000,
        "resp_pkts": 200,
        "resp_ip_bytes": 262000,
        "tunnel_parents": [],
    }

    print("\n── Step 1: Raw Zeek conn.log record ────────────────────────")
    for k, v in raw_zeek_record.items():
        print(f"  {k}: {v}")

    # -----------------------------------------------------------------------
    # Step 2: Parse into FlowRecord (Pydantic model)
    # -----------------------------------------------------------------------

    from app.parsers import parse_zeek_conn

    flows = parse_zeek_conn([raw_zeek_record])
    flow = flows[0]

    print("\n── Step 2: Parsed FlowRecord ────────────────────────────")
    print(f"  id:              {flow.id}")
    print(f"  src:             {flow.src_ip}:{flow.src_port}")
    print(f"  dst:             {flow.dst_ip}:{flow.dst_port}")
    print(f"  proto:           {flow.transport_proto}/{flow.app_proto}")
    print(f"  duration:        {flow.duration_sec}s")
    print(f"  bytes:           {flow.bytes_from_src} → {flow.bytes_from_dst}")
    print(f"  state:           {flow.state}")

    # -----------------------------------------------------------------------
    # Step 3: FlowDB row (what gets persisted)
    # -----------------------------------------------------------------------

    from app.db_models import FlowDB

    job_id = "dry-run-001"
    flow_db = FlowDB(
        id=f"{job_id}:{flow.id}",
        job_id=job_id,
        src_ip=flow.src_ip,
        src_port=flow.src_port,
        dst_ip=flow.dst_ip,
        dst_port=flow.dst_port,
        transport_proto=flow.transport_proto,
        app_proto=flow.app_proto,
        start_time=flow.start_time,
        end_time=flow.end_time,
        duration_sec=flow.duration_sec,
        bytes_from_src=flow.bytes_from_src,
        bytes_from_dst=flow.bytes_from_dst,
        packets_from_src=flow.packets_from_src,
        packets_from_dst=flow.packets_from_dst,
        tcp_flags_summary=flow.tcp_flags_summary,
        state=flow.state,
        extra=flow.extra,
    )

    print("\n── Step 3: FlowDB row (what gets persisted) ─────────────")
    print(f"  id:              {flow_db.id}")
    print(f"  job_id:          {flow_db.job_id}")
    print(f"  src_ip (indexed):{flow_db.src_ip}")
    print(f"  dst_ip (indexed):{flow_db.dst_ip}")
    print(f"  dst_port:        {flow_db.dst_port}")
    print(f"  proto:           {flow_db.transport_proto}/{flow_db.app_proto}")
    print(f"  duration_sec:    {flow_db.duration_sec}")
    print(f"  bytes_total:     {flow_db.bytes_from_src + flow_db.bytes_from_dst}")

    # -----------------------------------------------------------------------
    # Step 4: AnalysisContext (what the LLM interface receives)
    # -----------------------------------------------------------------------

    from app.core.interfaces import AnalysisContext

    ctx = AnalysisContext(
        job_id=job_id,
        exercise_id="icedid_c2_sample",
        mode="single_window",
        high_priority_flow_ids=[flow_db.id],
        alert_ids=[],
        metadata={"pcap_name": "icedid_traffic.pcap"},
    )

    print("\n── Step 4: AnalysisContext (LLM input contract) ─────────")
    print(f"  job_id:          {ctx.job_id}")
    print(f"  exercise_id:     {ctx.exercise_id}")
    print(f"  mode:            {ctx.mode}")
    print(f"  flow_ids:        {ctx.high_priority_flow_ids}")
    print(f"  alert_ids:       {ctx.alert_ids}")
    print(f"  metadata:        {ctx.metadata}")

    # -----------------------------------------------------------------------
    # Step 5: Finding (LLM output contract)
    # -----------------------------------------------------------------------

    from app.core.interfaces import Finding

    finding = Finding(
        mitre_technique_id="T1071.001",
        confidence_score=0.92,
        raw_evidence_snippet=(
            f"TCP {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port} "
            f"TLS, duration={flow.duration_sec}s, "
            f"bytes_out={flow.bytes_from_src}, bytes_in={flow.bytes_from_dst}"
        ),
        rationale=(
            "Long-duration TLS connection to external IP on port 443 with "
            "periodic beaconing pattern (250KB response). Consistent with "
            "IcedID C2 communication over HTTPS."
        ),
        severity="critical",
        affected_hosts=[flow.src_ip],
        classification="IcedID",
        attack_chain_stage="Command and Control",
    )

    print("\n── Step 5: Finding (LLM output contract) ────────────────")
    print(f"  mitre_id:        {finding.mitre_technique_id}")
    print(f"  confidence:      {finding.confidence_score}")
    print(f"  severity:        {finding.severity}")
    print(f"  classification:  {finding.classification}")
    print(f"  kill_chain:      {finding.attack_chain_stage}")
    print(f"  affected_hosts:  {finding.affected_hosts}")
    print("  evidence:")
    print(f"    {finding.raw_evidence_snippet}")
    print("  rationale:")
    print(f"    {finding.rationale}")

    # -----------------------------------------------------------------------
    # Step 6: EvidenceDB (Finding ↔ Flow linkage)
    # -----------------------------------------------------------------------

    from app.db_models import EvidenceDB

    evidence = EvidenceDB(
        id="ev-001",
        finding_id="finding-T1071.001-dry-run",
        flow_id=flow_db.id,
        relationship="supports",
        snippet=finding.raw_evidence_snippet,
    )

    print("\n── Step 6: EvidenceDB (Finding ↔ Flow many-to-many) ─────")
    print(f"  id:              {evidence.id}")
    print(f"  finding_id:      {evidence.finding_id}")
    print(f"  flow_id:         {evidence.flow_id}")
    print(f"  relationship:    {evidence.relationship}")
    print(f"  snippet:         {evidence.snippet[:60]}...")

    print("\n" + "=" * 70)
    print("✅ Dry run complete — full data flow demonstrated")
    print("   Zeek JSON → FlowRecord → FlowDB → AnalysisContext → Finding → EvidenceDB")
    print("=" * 70)


if __name__ == "__main__":
    main()
