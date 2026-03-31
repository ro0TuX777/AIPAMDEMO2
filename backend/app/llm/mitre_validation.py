"""MITRE ATT&CK validation helpers extracted from LLMClient.

These are standalone functions so they can be used from LLMClient or anywhere
else that needs MITRE validation without importing the full client.
"""

from __future__ import annotations

from typing import Dict, List

from ..mitre_database import get_technique_name, validate_and_fix_technique, validate_technique_id


def get_mitre_technique_name(tech_id: str) -> str:
    """Get the name for a MITRE ATT&CK technique ID."""
    return get_technique_name(tech_id)


def validate_and_fix_mitre_techniques(techniques: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Validate MITRE technique IDs and fix incorrect names.

    Args:
        techniques: List of {"id": "T1XXX", "name": "..."} dicts.

    Returns:
        List of validated/corrected technique dicts.
    """
    validated: list[dict[str, str]] = []
    for tech in techniques:
        if not isinstance(tech, dict) or "id" not in tech:
            continue

        tech_id = tech.get("id", "")
        provided_name = tech.get("name", "")

        fixed_id, fixed_name, was_corrected = validate_and_fix_technique(tech_id, provided_name)
        is_valid, _ = validate_technique_id(tech_id)

        if not is_valid:
            print(f"Warning: Invalid MITRE technique ID '{tech_id}' with name '{provided_name}'")

        validated.append({
            "id": fixed_id,
            "name": fixed_name,
            "_validated": is_valid,
            "_corrected": was_corrected,
        })

    return validated


def validate_attack_chain(attack_chain: List[Dict]) -> List[Dict]:
    """Validate and fix MITRE techniques in attack chain items.

    Args:
        attack_chain: List of attack chain stage dicts.

    Returns:
        Attack chain with validated MITRE techniques.
    """
    validated_chain: list[dict] = []
    for item in attack_chain:
        if not isinstance(item, dict):
            continue

        validated_item = item.copy()
        if "mitre_techniques" in item and item["mitre_techniques"]:
            validated_item["mitre_techniques"] = validate_and_fix_mitre_techniques(
                item["mitre_techniques"]
            )
        validated_chain.append(validated_item)

    return validated_chain


def validate_output_mitre(output: "LLMOutput") -> "LLMOutput":  # noqa: F821
    """Validate and fix all MITRE techniques in an LLMOutput object.

    This is the main entry point for MITRE validation, called after
    the LLM output is parsed.

    Args:
        output: The LLMOutput object to validate.

    Returns:
        The same LLMOutput with validated/corrected MITRE techniques.
    """
    from ..models import AttackChainItem, MitreTechnique

    # Validate attack_chain techniques
    if output.attack_chain:
        validated_chain = []
        for item in output.attack_chain:
            if isinstance(item, dict):
                item_dict = item
            else:
                item_dict = item.model_dump() if hasattr(item, "model_dump") else item.__dict__

            if "mitre_techniques" in item_dict and item_dict["mitre_techniques"]:
                validated_techs = validate_and_fix_mitre_techniques(
                    [t.model_dump() if hasattr(t, "model_dump") else t for t in item_dict["mitre_techniques"]]
                )
                cleaned_techs = [
                    {"id": t["id"], "name": t["name"]}
                    for t in validated_techs
                ]
                item_dict["mitre_techniques"] = [MitreTechnique(**t) for t in cleaned_techs]

            validated_chain.append(
                AttackChainItem(**item_dict) if isinstance(item, AttackChainItem) else item_dict
            )

        output.attack_chain = validated_chain

    # Validate mitre_techniques_overall
    if output.mitre_techniques_overall:
        validated_overall = validate_and_fix_mitre_techniques(
            [t.model_dump() if hasattr(t, "model_dump") else t for t in output.mitre_techniques_overall]
        )
        cleaned_overall = [
            {"id": t["id"], "name": t["name"]}
            for t in validated_overall
        ]
        output.mitre_techniques_overall = [MitreTechnique(**t) for t in cleaned_overall]

    return output

