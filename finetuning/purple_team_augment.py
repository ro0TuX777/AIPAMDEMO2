#!/usr/bin/env python3
"""
Phase 6.4 — Purple Team Augmentation Bridge

Self-Healing Forensic Loop: Takes confirmed findings (or a fail list),
generates synthetic PCAP variants via the DAWN simulate.traffic_pattern
link, and injects them into the training pipeline.

Usage:
    # From a findings JSON file:
    python purple_team_augment.py --findings path/to/findings.json --count 50

    # From a fail list (families the model is struggling with):
    python purple_team_augment.py --fail-list IcedID,Emotet,Pikabot --count 100

    # Dry-run to validate pipeline:
    python purple_team_augment.py --fail-list IcedID --count 3 --dry-run
"""

import argparse
import importlib.util
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# DAWN seed per constitutional requirement
DAWN_RANDOM_SEED = 3407
random.seed(DAWN_RANDOM_SEED)

# Project structure
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DAWN_ROOT = PROJECT_ROOT.parent / "DAWN"
LINKS_DIR = DAWN_ROOT / "dawn" / "links"
SYNTHETIC_DATA_DIR = PROJECT_ROOT / "finetuning" / "data" / "raw" / "synthetic"


# =============================================================================
# DAWN Link Loading (from closed_loop_test.py pattern)
# =============================================================================

def _load_link(link_name: str):
    """Load a DAWN link's run.py by explicit file path."""
    run_path = LINKS_DIR / link_name / "run.py"
    if not run_path.exists():
        raise FileNotFoundError(
            f"DAWN link not found: {run_path}\n"
            f"  Ensure DAWN repo is at: {DAWN_ROOT}"
        )
    spec = importlib.util.spec_from_file_location(
        f"dawn_link_{link_name}", str(run_path)
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# =============================================================================
# Fake DAWN context (matches closed_loop_test.py pattern)
# =============================================================================

class _FakeSandbox:
    def __init__(self, sandbox_dir: Path):
        self.dir = sandbox_dir
        self.artifacts: dict = {}

    def publish(self, artifact: str, filename: str, obj, schema: str = "json"):
        out = self.dir / filename
        if schema == "text":
            out.write_text(obj if isinstance(obj, str) else str(obj))
        else:
            with open(out, "w") as f:
                json.dump(obj, f, indent=2, default=str)
        self.artifacts[artifact] = {"path": str(out), "schema": schema}
        return str(out)


class _FakeLedger:
    def __init__(self):
        self.events: list = []

    def log_event(self, **kwargs):
        self.events.append(kwargs)


def _make_context(project_id: str, sandbox_dir: Path, findings_path: str):
    """Build a fake DAWN context for simulate.traffic_pattern."""
    # Create empty flow IR
    flow_path = sandbox_dir / "flow_ir.json"
    with open(flow_path, "w") as f:
        json.dump({"flows": []}, f)

    return {
        "project_id": project_id,
        "project_root": str(sandbox_dir),
        "pipeline_id": "purple_team_augment",
        "artifact_store": {
            "aipam.findings.reviewed": {
                "path": findings_path, "schema": "json"
            },
            "aipam.findings.ir": {
                "path": findings_path, "schema": "json"
            },
            "aipam.flow.ir": {
                "path": str(flow_path), "schema": "json"
            },
        },
        "sandbox": _FakeSandbox(sandbox_dir),
        "ledger": _FakeLedger(),
        "run_id": f"augment-{int(time.time())}",
    }


# =============================================================================
# Finding Builders
# =============================================================================

# MITRE → malware family mapping for fail-list mode
FAMILY_MITRE_MAP = {
    "IcedID":    {"mitre": "T1071.001", "desc": "IcedID C2 beacon over HTTPS",
                  "dst": "185.220.101.42", "port": 443},
    "Emotet":    {"mitre": "T1059.001", "desc": "Emotet PowerShell dropper callback",
                  "dst": "45.33.32.156", "port": 80},
    "Pikabot":   {"mitre": "T1071.001", "desc": "Pikabot loader C2 communication",
                  "dst": "192.42.116.199", "port": 443},
    "Qakbot":    {"mitre": "T1041", "desc": "Qakbot data exfiltration via HTTPS",
                  "dst": "23.111.114.52", "port": 443},
    "Cobalt":    {"mitre": "T1071.001", "desc": "Cobalt Strike beacon HTTP/S channel",
                  "dst": "104.21.90.100", "port": 443},
    "Dridex":    {"mitre": "T1027", "desc": "Dridex obfuscated payload transfer",
                  "dst": "31.41.44.97", "port": 8443},
    "TrickBot":  {"mitre": "T1055", "desc": "TrickBot lateral movement via SMB",
                  "dst": "10.0.0.50", "port": 445},
    "BazarLoader": {"mitre": "T1071.001", "desc": "BazarLoader DNS-over-HTTPS C2",
                    "dst": "91.195.240.94", "port": 443},
}


def build_findings_from_fail_list(
    fail_list: List[str],
    count: int,
) -> List[Dict]:
    """Generate synthetic findings from a list of failing malware families.

    Creates `count` variant findings per family with jittered parameters.
    """
    all_findings = []

    for family in fail_list:
        family = family.strip()
        template = FAMILY_MITRE_MAP.get(
            family,
            {"mitre": "T1071.001", "desc": f"{family} C2 activity",
             "dst": "10.10.10.10", "port": 443},
        )

        for variant_idx in range(count):
            # Jitter source IP
            src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

            # Jitter destination (slight variation)
            dst_parts = template["dst"].split(".")
            dst_parts[-1] = str(min(254, int(dst_parts[-1]) + random.randint(0, 5)))
            dst_ip = ".".join(dst_parts)

            # Jitter port
            port = template["port"] + random.choice([0, 0, 0, 1, -1, 8000])
            port = max(1, min(65535, port))

            all_findings.append({
                "mitre_technique_id": template["mitre"],
                "severity": random.choice(["HIGH", "HIGH", "CRITICAL"]),
                "confidence_score": round(random.uniform(0.85, 0.98), 2),
                "classification": f"{family} ({template['mitre']})",
                "description": template["desc"],
                "rationale": f"Variant {variant_idx}: {template['desc']}",
                "raw_evidence_snippet": (
                    f"{src_ip} -> {dst_ip}:{port} TCP "
                    f"beacon interval ~{random.randint(30, 120)}s"
                ),
                "affected_hosts": [src_ip],
                "requires_review": False,
                "_family": family,
                "_variant_index": variant_idx,
            })

    return all_findings


def load_findings_from_file(findings_path: str) -> List[Dict]:
    """Load confirmed findings from a JSON file."""
    with open(findings_path) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    # Filter to confirmed only
    confirmed = [f for f in findings if not f.get("requires_review", False)]

    if not confirmed:
        confirmed = findings  # Use all if none explicitly confirmed

    return confirmed


# =============================================================================
# PCAP Generation (minimal valid PCAP for when Scapy isn't available)
# =============================================================================

def write_minimal_pcap(
    path: Path,
    src_ip: str = "10.0.0.100",
    dst_ip: str = "185.220.101.42",
    dst_port: int = 443,
    num_packets: int = 10,
    label: str = "synthetic",
) -> None:
    """Write a minimal valid PCAP matching the finding parameters."""
    # PCAP global header
    header = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4, 2, 4, 0, 0, 65535, 1,
    )

    packets_raw = []
    ts = int(time.time())

    src_octets = [int(o) for o in src_ip.split(".")]
    dst_octets = [int(o) for o in dst_ip.split(".")]

    for i in range(num_packets):
        eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"
        payload = f"AIPAM-{label}-{i}".encode()

        ip_hdr = bytes([
            0x45, 0x00,
            0x00, 50 + len(payload),
            0x00, i % 256,
            0x00, 0x00,
            0x40, 0x06,
            0x00, 0x00,
            *src_octets,
            *dst_octets,
        ])

        sport = 49152 + random.randint(0, 16383)
        tcp_hdr = bytes([
            (sport >> 8) & 0xFF, sport & 0xFF,
            (dst_port >> 8) & 0xFF, dst_port & 0xFF,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02,
            0xFF, 0xFF,
            0x00, 0x00,
            0x00, 0x00,
        ])

        raw = eth + ip_hdr + tcp_hdr + payload
        pkt_header = struct.pack("<IIII", ts + i, 0, len(raw), len(raw))
        packets_raw.append(pkt_header + raw)

    with open(path, "wb") as f:
        f.write(header)
        for pkt in packets_raw:
            f.write(pkt)


# =============================================================================
# Core Pipeline
# =============================================================================

def generate_synthetic_batch(
    findings: List[Dict],
    output_dir: Path,
    dry_run: bool = False,
    use_dawn_link: bool = True,
) -> Dict[str, Any]:
    """Generate synthetic PCAPs and metadata for each finding.

    Returns summary stats.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    stats = {
        "total_findings": len(findings),
        "pcaps_generated": 0,
        "families": {},
        "errors": 0,
    }

    # Try to load DAWN link
    sim_module = None
    if use_dawn_link:
        try:
            sim_module = _load_link("simulate.traffic_pattern")
            print(f"  ✓ DAWN simulate.traffic_pattern loaded")
        except FileNotFoundError as e:
            print(f"  ⚠️  {e}")
            print(f"  Falling back to minimal PCAP generation")

    for i, finding in enumerate(findings):
        family = finding.get("_family", finding.get("classification", "unknown"))
        # Clean family name for filesystem
        family_clean = family.split("(")[0].strip().replace(" ", "_")
        variant_idx = finding.get("_variant_index", i)

        family_dir = output_dir / family_clean
        family_dir.mkdir(parents=True, exist_ok=True)

        pcap_name = f"variant_{variant_idx:04d}.pcap"
        pcap_path = family_dir / pcap_name
        metadata_path = family_dir / f"variant_{variant_idx:04d}.metadata.json"

        # Extract network parameters
        hosts = finding.get("affected_hosts", ["10.0.0.100"])
        src_ip = hosts[0] if hosts else "10.0.0.100"
        evidence = finding.get("raw_evidence_snippet", "")

        # Parse dst from evidence or use default
        dst_ip = "185.220.101.42"
        dst_port = 443
        if "->" in evidence:
            try:
                dst_part = evidence.split("->")[1].strip().split()[0]
                if ":" in dst_part:
                    dst_ip, dst_port = dst_part.split(":")
                    dst_port = int(dst_port)
                else:
                    dst_ip = dst_part
            except (IndexError, ValueError):
                pass

        if dry_run:
            print(f"  [{i+1}/{len(findings)}] [DRY-RUN] {family_clean}/variant_{variant_idx:04d} "
                  f"({finding.get('mitre_technique_id', '?')})")
        else:
            # Strategy 1: Use DAWN link for full Scapy script
            pcap_generated = False

            if sim_module and not dry_run:
                try:
                    with tempfile.TemporaryDirectory(prefix="augment_") as tmpdir:
                        tmpdir = Path(tmpdir)
                        sandbox_dir = tmpdir / "sandbox"
                        sandbox_dir.mkdir()

                        # Write single finding
                        findings_file = tmpdir / "findings.json"
                        with open(findings_file, "w") as f:
                            json.dump({
                                "job_id": f"augment-{family_clean}-{variant_idx}",
                                "findings": [finding],
                            }, f)

                        ctx = _make_context(
                            f"augment-{family_clean}", sandbox_dir,
                            str(findings_file)
                        )

                        sim_config = {"spec": {"config": {
                            "model_name": "llama3.1:8b",
                            "llm_endpoint": "http://localhost:11434",
                            "safe_mode": True,
                            "max_findings": 1,
                        }}}

                        result = sim_module.run(ctx, sim_config)

                        # Check if script was generated
                        sim_artifact = ctx["sandbox"].artifacts.get("aipam.simulation.py")
                        if sim_artifact:
                            script_path = Path(sim_artifact["path"])
                            script_content = script_path.read_text()

                            # Execute script in dry-run mode to produce PCAP
                            exec_result = subprocess.run(
                                [sys.executable, str(script_path),
                                 "--dry-run", "--pcap", str(pcap_path)],
                                capture_output=True, text=True, timeout=30,
                            )

                            if pcap_path.exists() and pcap_path.stat().st_size > 24:
                                pcap_generated = True

                except Exception as e:
                    print(f"  [{i+1}/{len(findings)}] DAWN link error: {e}")

            # Strategy 2: Fallback to minimal PCAP
            if not pcap_generated and not dry_run:
                write_minimal_pcap(
                    pcap_path,
                    src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                    num_packets=random.randint(5, 20),
                    label=family_clean,
                )
                pcap_generated = True

            if pcap_generated:
                print(f"  [{i+1}/{len(findings)}] ✓ {family_clean}/variant_{variant_idx:04d} "
                      f"({pcap_path.stat().st_size} bytes)")

        # Write label sidecar metadata
        metadata = {
            "label": family_clean,
            "normalized_label": family_clean.lower(),
            "mitre_technique_id": finding.get("mitre_technique_id", "T0000"),
            "source": "synthetic",
            "variant_index": variant_idx,
            "severity": finding.get("severity", "HIGH"),
            "confidence_score": finding.get("confidence_score", 0.90),
            "description": finding.get("description", ""),
            "rationale": finding.get("rationale", ""),
            "affected_hosts": finding.get("affected_hosts", []),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "dawn_seed": DAWN_RANDOM_SEED,
        }

        if not dry_run:
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

        stats["pcaps_generated"] += 1
        stats["families"][family_clean] = stats["families"].get(family_clean, 0) + 1

    return stats


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 6.4 — Purple Team Augmentation Bridge (Self-Healing Loop)"
    )
    parser.add_argument(
        "--findings", type=str, default=None,
        help="Path to findings JSON file (aipam.findings.reviewed format)"
    )
    parser.add_argument(
        "--fail-list", type=str, default=None,
        help="Comma-separated list of failing malware families (e.g., IcedID,Emotet)"
    )
    parser.add_argument(
        "--count", type=int, default=50,
        help="Number of synthetic variants per finding/family"
    )
    parser.add_argument(
        "--output-dir", type=str,
        default=str(SYNTHETIC_DATA_DIR),
        help="Output directory for synthetic PCAPs"
    )
    parser.add_argument(
        "--process", action="store_true",
        help="Auto-trigger process_training_data.py after generation"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate pipeline without generating PCAPs"
    )
    args = parser.parse_args()

    if not args.findings and not args.fail_list:
        print("Error: Must specify --findings or --fail-list")
        parser.print_help()
        return

    print("=" * 60)
    print("Phase 6.4 — Purple Team Augmentation Bridge")
    print(f"Seed: {DAWN_RANDOM_SEED} (DAWN Constitutional)")
    if args.dry_run:
        print("[DRY-RUN MODE]")
    print("=" * 60)

    # 1. Build findings
    if args.fail_list:
        families = [f.strip() for f in args.fail_list.split(",")]
        print(f"\n[1/4] Building findings from fail list: {families}")
        print(f"  Generating {args.count} variants per family")
        findings = build_findings_from_fail_list(families, count=args.count)
    else:
        print(f"\n[1/4] Loading findings from: {args.findings}")
        findings = load_findings_from_file(args.findings)
        # Expand each finding to `count` variants
        expanded = []
        for finding in findings:
            family = finding.get("classification", "unknown")
            for v in range(args.count):
                variant = dict(finding)
                variant["_family"] = family
                variant["_variant_index"] = v
                # Jitter source IP
                variant["affected_hosts"] = [
                    f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                ]
                expanded.append(variant)
        findings = expanded

    print(f"  Total findings to process: {len(findings)}")

    # 2. Generate synthetic PCAPs
    output_dir = Path(args.output_dir)
    print(f"\n[2/4] Generating synthetic PCAPs → {output_dir}")

    stats = generate_synthetic_batch(
        findings, output_dir,
        dry_run=args.dry_run,
    )

    # 3. Summary
    print(f"\n[3/4] Generation Summary:")
    print(f"  Total PCAPs: {stats['pcaps_generated']}")
    print(f"  Families:")
    for family, count in sorted(stats["families"].items()):
        print(f"    {family}: {count} variants")
    if stats["errors"]:
        print(f"  Errors: {stats['errors']}")

    # 4. Training injection
    if args.process and not args.dry_run:
        print(f"\n[4/4] Triggering training data processing...")
        result = subprocess.run(
            [sys.executable, "finetuning/process_training_data.py",
             "--dataset", "synthetic"],
            cwd=str(PROJECT_ROOT),
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"  ✓ Synthetic data processed into training samples")
        else:
            print(f"  ⚠️  Processing returned code {result.returncode}")
            if result.stderr:
                print(f"  {result.stderr[-200:]}")
    elif args.dry_run:
        print(f"\n[4/4] [DRY-RUN] Would trigger: process_training_data.py --dataset synthetic")
    else:
        print(f"\n[4/4] Skipping auto-processing (use --process to trigger)")
        print(f"  Manual: python finetuning/process_training_data.py --dataset synthetic")

    # DAWN Ledger
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "finetuning"))
        from dawn_training_ledger import log_training_event
        log_training_event("purple_team_augment", {
            "phase": "6.4",
            "families": list(stats["families"].keys()),
            "total_pcaps": stats["pcaps_generated"],
            "count_per_family": args.count,
            "random_seed": DAWN_RANDOM_SEED,
        })
        print(f"\n[DAWN] Augmentation event logged to ledger")
    except Exception:
        pass

    print(f"\n{'=' * 60}")
    if args.dry_run:
        print(f"✓ Dry-run validation passed!")
    else:
        print(f"✓ Purple Team Augmentation complete!")
        print(f"  Synthetic PCAPs: {output_dir}")
        print(f"  Next: python finetuning/process_training_data.py --dataset synthetic")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
