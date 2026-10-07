"""
Targeted tests for evidence-aware verification, evidence sufficiency,
chain completeness, attack vs benign hypotheses, and INSUFFICIENT_EVIDENCE verdicts.
"""

import json
from pathlib import Path
import pytest
from backend.evaluation.evaluator import BenchmarkEvaluator

DATASETS_DIR = Path(__file__).resolve().parent.parent / "data" / "datasets"


def test_1_strong_attack_yields_likely_attack():
    """Validates: Strong attack -> LIKELY_ATTACK with high sufficiency and completeness."""
    with open(DATASETS_DIR / "insider_usb_exfil.json", "r", encoding="utf-8") as f:
        logs = json.load(f)

    with open(DATASETS_DIR / "benign_baseline.json", "r", encoding="utf-8") as f:
        baseline = json.load(f)

    evaluator = BenchmarkEvaluator()
    report = evaluator.analyze_dataset(logs, baseline_events=baseline)

    assert report.final_verdict == "LIKELY_ATTACK"
    assert report.is_attack is True
    # Independent scores check
    assert report.overall_risk_score >= 80.0
    assert report.evidence_sufficiency_score >= 70.0
    assert report.chain_completeness_score >= 70.0
    # Hypotheses check
    assert len(report.attack_hypothesis) > 20
    assert len(report.benign_hypothesis) > 20
    assert "Attack Hypothesis is strongly favored" in report.hypothesis_evaluation


def test_2_legitimate_activity_yields_normal():
    """Validates: Legitimate activity -> NORMAL with zero false alarms."""
    with open(DATASETS_DIR / "benign_baseline.json", "r", encoding="utf-8") as f:
        logs = json.load(f)

    evaluator = BenchmarkEvaluator()
    report = evaluator.analyze_dataset(logs)

    assert report.final_verdict == "NORMAL"
    assert report.verdict == "BENIGN_BASELINE"
    assert report.is_attack is False
    assert report.overall_risk_score == 0.0
    assert report.evidence_sufficiency_score == 0.0
    assert report.chain_completeness_score == 0.0
    assert "No adversarial" in report.attack_hypothesis or "NORMAL" in report.hypothesis_evaluation


def test_3_suspicious_incomplete_evidence_yields_insufficient_evidence():
    """Validates: Suspicious but incomplete evidence -> INSUFFICIENT_EVIDENCE (not forced into attack)."""
    # A single isolated suspicious event (external login at night, but no execution, collection, or exfiltration)
    isolated_suspicious_logs = [
        {
            "event_id": "susp-single-001",
            "timestamp": "2026-10-06T03:14:00Z",
            "event_type": "AUTH_LOGIN",
            "source": "Windows-Security-4624",
            "actor_user": "external_contractor",
            "source_ip": "198.51.100.77",
            "source_host": "REMOTE-LAPTOP",
            "dest_host": "WKS-DEV-01",
            "raw_log": "EventID 4624: Remote interactive logon for external_contractor from 198.51.100.77 at 03:14 UTC"
        }
    ]

    evaluator = BenchmarkEvaluator()
    report = evaluator.analyze_dataset(isolated_suspicious_logs)

    assert report.final_verdict == "INSUFFICIENT_EVIDENCE"
    assert report.is_attack is False, "Must NOT force isolated anomaly into attack verdict!"
    assert report.overall_risk_score <= 40.0
    assert report.evidence_sufficiency_score <= 60.0
    assert report.chain_completeness_score <= 50.0
    assert len(report.timeline) == 1
    # Check that stage acknowledges missing/partial evidence
    stage = report.timeline[0]
    assert stage.status in ("PARTIAL", "CONFIRMED")
    assert len(stage.missing_evidence) > 0
    assert "INSUFFICIENT_EVIDENCE verdict selected" in report.hypothesis_evaluation


def test_4_mixed_noise_still_detects_attack():
    """Validates: Mixed noise -> existing attack detection still works accurately."""
    with open(DATASETS_DIR / "mixed_enterprise.json", "r", encoding="utf-8") as f:
        logs = json.load(f)

    with open(DATASETS_DIR / "benign_baseline.json", "r", encoding="utf-8") as f:
        baseline = json.load(f)

    evaluator = BenchmarkEvaluator()
    report = evaluator.analyze_dataset(logs, baseline_events=baseline)

    assert report.final_verdict == "LIKELY_ATTACK"
    assert report.is_attack is True
    assert "edward_snow" in report.actors_involved
    assert report.overall_risk_score >= 80.0
    assert report.evidence_sufficiency_score >= 70.0


def test_5_every_evidence_reference_maps_to_real_source_event():
    """Validates: Every evidence reference maps to a real source event (no fabricated evidence)."""
    with open(DATASETS_DIR / "insider_usb_exfil.json", "r", encoding="utf-8") as f:
        raw_logs = json.load(f)

    evaluator = BenchmarkEvaluator()
    report = evaluator.analyze_dataset(raw_logs)

    raw_event_ids = {item["event_id"] for item in raw_logs}

    assert len(report.timeline) > 0
    for stage in report.timeline:
        # Check that event_id exists in the raw input logs
        assert stage.proof.event_id in raw_event_ids, f"Event ID {stage.proof.event_id} must exist in input data!"
        assert stage.proof.raw_citation is not None
        assert len(stage.proof.raw_citation) > 0
        assert stage.source_event is not None
        assert stage.status in ("CONFIRMED", "PARTIAL", "MISSING", "CONTRADICTED")
        # Check supporting evidence is not empty
        assert len(stage.supporting_evidence) > 0

    # Check graph edge traceability
    suspicious_edges = [e for e in report.graph_edges if e.is_suspicious]
    for edge in suspicious_edges:
        assert edge.event_id in raw_event_ids
