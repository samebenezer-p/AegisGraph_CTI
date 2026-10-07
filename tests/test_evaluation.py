"""
Test suite validating data normalization, graph generation, multi-stage attack reconstruction,
and false positive suppression.
"""

import json
from pathlib import Path
import pytest
from backend.evaluation.evaluator import BenchmarkEvaluator

DATASETS_DIR = Path(__file__).resolve().parent.parent / "data" / "datasets"


def test_benign_baseline_zero_false_positives():
    """Validates that clean enterprise logs produce ZERO false alarms (Precision rule)."""
    with open(DATASETS_DIR / "benign_baseline.json", "r", encoding="utf-8") as f:
        logs = json.load(f)

    evaluator = BenchmarkEvaluator()
    report = evaluator.analyze_dataset(logs)

    assert report.is_attack is False, "Clean baseline MUST NOT raise an attack alert!"
    assert report.verdict == "BENIGN_BASELINE"
    assert report.overall_risk_score == 0.0
    assert len(report.timeline) == 0, "No attack stages should be generated for clean logs"
    assert report.risk_level == "CLEAN"


def test_insider_usb_exfiltration_prompt_scenario():
    """Validates the exact scenario described in the user prompt."""
    with open(DATASETS_DIR / "insider_usb_exfil.json", "r", encoding="utf-8") as f:
        logs = json.load(f)

    with open(DATASETS_DIR / "benign_baseline.json", "r", encoding="utf-8") as f:
        baseline = json.load(f)

    evaluator = BenchmarkEvaluator()
    report = evaluator.analyze_dataset(logs, baseline_events=baseline)

    assert report.is_attack is True, "Insider threat attack MUST be detected!"
    assert report.verdict == "MALICIOUS_ATTACK_CHAIN"
    assert "edward_snow" in report.actors_involved
    assert "WKS-FIN-04" in report.devices_involved
    assert report.overall_risk_score >= 80.0
    assert len(report.timeline) >= 3

    # Check evidence proof for every stage
    for stage in report.timeline:
        assert stage.proof is not None
        assert stage.proof.raw_citation is not None
        assert stage.proof.confidence > 0.5
        assert len(stage.proof.justification) > 5

    # Check mitigations
    assert len(report.mitigations) > 0
    categories = {m.category for m in report.mitigations}
    assert "CONTAINMENT" in categories


def test_benchmark_suite_metrics():
    """Validates Precision, Recall, and False Positive Rate across all test datasets."""
    scenarios = [
        {
            "name": "Benign Enterprise Baseline",
            "file": "benign_baseline.json",
            "ground_truth_is_attack": False
        },
        {
            "name": "Insider Threat USB Exfiltration",
            "file": "insider_usb_exfil.json",
            "ground_truth_is_attack": True
        },
        {
            "name": "APT Lateral Movement",
            "file": "apt_lateral_movement.json",
            "ground_truth_is_attack": True
        },
        {
            "name": "Ransomware Outbreak",
            "file": "ransomware_outbreak.json",
            "ground_truth_is_attack": True
        },
        {
            "name": "Mixed Enterprise Traffic",
            "file": "mixed_enterprise.json",
            "ground_truth_is_attack": True
        }
    ]

    loaded = []
    for sc in scenarios:
        with open(DATASETS_DIR / sc["file"], "r", encoding="utf-8") as f:
            loaded.append({
                "name": sc["name"],
                "events": json.load(f),
                "ground_truth_is_attack": sc["ground_truth_is_attack"]
            })

    evaluator = BenchmarkEvaluator()
    results = evaluator.run_benchmark_suite(loaded)
    metrics = results["summary_metrics"]

    print("\nBENCHMARK RESULTS:", json.dumps(metrics, indent=2))
    assert metrics["false_positives"] == 0, "FPR must be 0.0 (Zero False Alarms on Clean Logs)"
    assert metrics["false_negatives"] == 0, "Must detect all genuine attacks"
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0
    assert metrics["evidence_citation_rate_pct"] == 100.0


if __name__ == "__main__":
    test_benign_baseline_zero_false_positives()
    test_insider_usb_exfiltration_prompt_scenario()
    test_benchmark_suite_metrics()
    print("\n[SUCCESS] ALL EVALUATION AND FORENSIC TESTS PASSED ACCURATELY!")
