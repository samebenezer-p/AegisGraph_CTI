"""
Risk Engine: Calculates composite threat risk scores and blast radius assessments.
Evaluates tactical progression depth, affected asset criticality, and attack velocity.
"""

from typing import List, Dict, Any, Tuple
from backend.models import AttackStage, MitreTactic


class RiskEngine:
    """Computes multi-dimensional risk scores and impact levels for cyber incidents."""

    # Tactic severity multipliers
    TACTIC_WEIGHTS = {
        MitreTactic.INITIAL_ACCESS: 15.0,
        MitreTactic.EXECUTION: 25.0,
        MitreTactic.PERSISTENCE: 35.0,
        MitreTactic.PRIVILEGE_ESCALATION: 50.0,
        MitreTactic.DEFENSE_EVASION: 60.0,
        MitreTactic.CREDENTIAL_ACCESS: 70.0,
        MitreTactic.DISCOVERY: 20.0,
        MitreTactic.LATERAL_MOVEMENT: 65.0,
        MitreTactic.COLLECTION: 75.0,
        MitreTactic.EXFILTRATION: 95.0,
        MitreTactic.IMPACT: 100.0,
    }

    @classmethod
    def calculate_risk(
        cls,
        stages: List[AttackStage],
        actors: List[str],
        devices: List[str],
        ips: List[str]
    ) -> Tuple[float, str, Dict[str, Any]]:
        """
        Calculates composite risk score (0.0 to 100.0) and assigns a severity rating.
        Returns: (overall_score, severity_level, breakdown)
        """
        if not stages:
            return (0.0, "CLEAN", {
                "progression_score": 0.0,
                "blast_radius_score": 0.0,
                "criticality_factor": 1.0,
                "summary": "No threat indicators detected. System operating within safe parameters."
            })

        # 1. Progression Score (Highest tactic reached + count of corroborating stages)
        max_tactic_weight = max(cls.TACTIC_WEIGHTS.get(s.tactic, 20.0) for s in stages)
        stage_depth_bonus = min(20.0, len(stages) * 4.0)
        progression_score = min(100.0, max_tactic_weight * 0.75 + stage_depth_bonus)

        # 2. Blast Radius Score (Entities involved)
        blast_entities = len(actors) + len(devices) + len(ips)
        blast_radius_score = min(100.0, blast_entities * 12.5)

        # 3. Criticality Factor (Domain Controllers, Exec, Finance assets)
        has_dc = any("dc" in d.lower() or "domain" in d.lower() for d in devices)
        has_sensitive_file = any("exfiltration" in s.tactic.value.lower() or "impact" in s.tactic.value.lower() for s in stages)
        criticality_factor = 1.0
        if has_dc:
            criticality_factor += 0.20
        if has_sensitive_file:
            criticality_factor += 0.15

        # Composite calculation
        raw_score = (progression_score * 0.65 + blast_radius_score * 0.35) * criticality_factor
        final_score = min(100.0, max(10.0, round(raw_score, 1)))

        # Categorization
        if final_score >= 85.0:
            severity = "CRITICAL"
        elif final_score >= 65.0:
            severity = "HIGH"
        elif final_score >= 40.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        breakdown = {
            "progression_score": round(progression_score, 1),
            "blast_radius_score": round(blast_radius_score, 1),
            "criticality_multiplier": round(criticality_factor, 2),
            "affected_identities_count": len(actors),
            "affected_hosts_count": len(devices),
            "summary": f"Calculated {severity} threat score of {final_score}/100 with blast radius across {len(devices)} endpoint(s)."
        }

        return final_score, severity, breakdown
