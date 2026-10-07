"""
Unit tests for ProvenanceGraphEngine, AnomalyDetector, and RiskEngine.
"""

from backend.engine.graph_engine import ProvenanceGraphEngine
from backend.engine.anomaly_detector import AnomalyDetector
from backend.engine.risk_engine import RiskEngine
from backend.models import NormalizedEvent, EventType, AttackStage, AttackEvidence, MitreTactic


def test_provenance_graph_building():
    engine = ProvenanceGraphEngine()

    e1 = NormalizedEvent(
        event_id="e1",
        timestamp="2026-10-06T01:00:00Z",
        event_type=EventType.AUTH_LOGIN,
        source="WinSec",
        actor_user="hacker",
        source_ip="185.220.101.5",
        dest_host="SRV-TARGET"
    )
    e2 = NormalizedEvent(
        event_id="e2",
        timestamp="2026-10-06T01:05:00Z",
        event_type=EventType.PROCESS_SPAWN,
        source="WinSec",
        actor_user="hacker",
        dest_host="SRV-TARGET",
        process_name="cmd.exe"
    )

    engine.ingest_events([e1, e2])
    nodes, edges = engine.get_exportable_graph()

    node_ids = {n.id for n in nodes}
    assert "user:hacker" in node_ids
    assert "host:SRV-TARGET" in node_ids
    assert "proc:cmd.exe" in node_ids
    assert len(edges) >= 2


def test_anomaly_detector_scoring():
    detector = AnomalyDetector()

    # Normal internal event
    normal_evt = NormalizedEvent(
        event_id="norm1",
        timestamp="2026-10-06T14:00:00Z",
        event_type=EventType.AUTH_LOGIN,
        source="WinSec",
        actor_user="alice",
        source_ip="192.168.1.50",
        dest_host="WKS-01"
    )
    score, reasons, details = detector.evaluate_event(normal_evt)
    assert score == 0.0
    assert len(reasons) == 0

    # Suspicious event: external IP, off-hours, high-risk process
    sus_evt = NormalizedEvent(
        event_id="sus1",
        timestamp="2026-10-06T02:30:00Z",
        event_type=EventType.PROCESS_SPAWN,
        source="WinSec",
        actor_user="unknown",
        source_ip="198.51.100.99",
        dest_host="DC-01",
        process_name="mimikatz.exe",
        process_command="mimikatz.exe privilege::debug"
    )
    score, reasons, details = detector.evaluate_event(sus_evt)
    assert score >= 0.70
    assert len(reasons) >= 3


def test_risk_engine_calculation():
    stage = AttackStage(
        stage_id=1,
        stage_name="Stage 1: USB Exfiltration",
        tactic=MitreTactic.EXFILTRATION,
        technique_id="T1052.001",
        technique_name="Exfiltration Over Removable Drive",
        timestamp="2026-10-06T02:26:00Z",
        actor="edward",
        affected_entities=["edward", "WKS-01"],
        description="USB exfil",
        proof=AttackEvidence(
            evidence_id="p1",
            event_id="e1",
            timestamp="2026-10-06T02:26:00Z",
            log_source="DLP",
            raw_citation="DLP transfer to USB",
            justification="USB exfil",
            confidence=0.95,
            indicators=["usb"]
        ),
        risk_contribution=95.0
    )

    score, severity, breakdown = RiskEngine.calculate_risk(
        stages=[stage],
        actors=["edward"],
        devices=["WKS-01"],
        ips=["198.51.100.42"]
    )

    assert score >= 65.0
    assert severity in ("CRITICAL", "HIGH")
