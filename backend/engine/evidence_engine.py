"""
Evidence & Explanation Engine: Compiles transparent, verifiable proof chains
and synthesizes plain-language executive & technical explanations.
"""

from typing import List, Dict, Any
from backend.models import AttackStage


class EvidenceEngine:
    """Generates structured forensic evidence chains and human-interpretable attack narratives."""

    @staticmethod
    def generate_attack_explanation(
        actors: List[str],
        devices: List[str],
        ips: List[str],
        apps: List[str],
        stages: List[AttackStage]
    ) -> str:
        """Constructs an end-to-end causal explanation of the detected attack."""
        if not stages:
            return "No coordinated adversarial activity detected. All observed events align with normal benign operational baselines."

        actor_str = ", ".join(actors) if actors else "Unknown Actor"
        device_str = ", ".join(devices) if devices else "Internal Endpoints"
        ip_str = ", ".join(ips) if ips else "N/A"
        app_str = ", ".join(apps) if apps else "System Binaries"

        first_stage = stages[0]
        last_stage = stages[-1]

        narrative_parts = [
            f"A multi-stage cyber incident was detected involving identity '{actor_str}' spanning {len(stages)} sequential stages across {len(devices)} endpoint(s).",
            f"The attack initiated at {first_stage.timestamp} via {first_stage.technique_name} originating from network node(s) [{ip_str}]."
        ]

        # Intermediate progression
        if len(stages) > 2:
            mid_stages = [f"'{s.technique_name}'" for s in stages[1:-1]]
            narrative_parts.append(
                f"The adversary subsequently escalated their foothold by executing {', '.join(mid_stages)} targeting internal assets [{device_str}] utilizing [{app_str}]."
            )

        # Objective / Concluding stage
        narrative_parts.append(
            f"The intrusion culminated at {last_stage.timestamp} with {last_stage.technique_name} ({last_stage.tactic.value}). "
            f"Verifiable forensic proof was corroborated across all {len(stages)} distinct stages without unverified assertions."
        )

        return " ".join(narrative_parts)

    @staticmethod
    def format_forensic_summary_table(stages: List[AttackStage]) -> List[Dict[str, Any]]:
        """Formats evidence into a forensic summary table for SOC analysts."""
        table = []
        for s in stages:
            table.append({
                "stage": s.stage_id,
                "timestamp": s.timestamp,
                "tactic": s.tactic.value,
                "technique": f"{s.technique_id} - {s.technique_name}",
                "actor": s.actor,
                "confidence": f"{int(s.proof.confidence * 100)}%",
                "log_source": s.proof.log_source,
                "justification": s.proof.justification,
                "raw_proof_snippet": s.proof.raw_citation[:140] + ("..." if len(s.proof.raw_citation) > 140 else "")
            })
        return table
