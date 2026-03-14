"""
Export Training Data Script (§12.5).

Extracts findings with user feedback (confirmed, false_positive, false_negative)
into a JSONL format suitable for TrafficLLM v2 fine-tuning.
"""

import json
import sys
from pathlib import Path
from sqlalchemy import select

# Add backend to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from backend.app.database_v2 import get_session_factory
from backend.app.models.finding import Finding

def export_findings(output_file: str):
    session_factory = get_session_factory()
    db = session_factory()

    q = select(Finding).where(Finding.feedback.isnot(None))
    findings = db.execute(q).scalars().all()

    print(f"Found {len(findings)} findings with feedback.")

    count = 0
    with open(output_file, "w") as f:
        for finding in findings:
            evidence = {}
            if finding.evidence_json:
                try:
                    evidence = json.loads(finding.evidence_json)
                except:
                    pass

            packet_hex = evidence.get("packet_hex")
            if not packet_hex:
                # If no direct hex, we can't train TrafficLLM v2 yet
                # In a real scenario, we might try to reconstruct from flow data
                continue

            # Map feedback to training labels
            # confirmed -> use original classification
            # false_positive -> normal
            # false_negative -> hopefully user provided a label in evidence or notes
            
            output_label = evidence.get("classification", "unknown")
            if finding.feedback == "false_positive":
                output_label = "normal"
            elif finding.feedback == "confirmed":
                output_label = evidence.get("classification", "unknown")
            
            # Construct the training record
            record = {
                "instruction": "Detect malware in this traffic",
                "input": f"<packet>: {packet_hex}",
                "output": output_label,
                "metadata": {
                    "finding_id": finding.finding_id,
                    "job_id": finding.job_id,
                    "feedback": finding.feedback,
                    "sensor": finding.sensor
                }
            }
            
            f.write(json.dumps(record) + "\n")
            count += 1

    print(f"Exported {count} records to {output_file}")

if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "traffic_training_v2.jsonl"
    export_findings(output)
