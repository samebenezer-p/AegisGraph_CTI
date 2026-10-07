"""
Attack Reconstructor Engine: Correlates events across entities into multi-stage attack chains.
Maps stages to MITRE ATT&CK tactics, enforces the False Positive Suppression Rule,
and extracts complete attack storylines.
"""

from typing import List, Dict, Any, Set, Tuple, Optional
from datetime import datetime
from backend.models import (
    NormalizedEvent, AttackStage, AttackEvidence, MitreTactic, EventType
)
from backend.engine.anomaly_detector import AnomalyDetector
from backend.engine.graph_engine import ProvenanceGraphEngine


class AttackReconstructor:
    """Reconstructs coherent multi-stage attack chains while suppressing benign false alarms."""

    def __init__(self, anomaly_detector: Optional[AnomalyDetector] = None):
        self.detector = anomaly_detector or AnomalyDetector()
        self.unconfirmed_candidate_chains: List[Dict[str, Any]] = []

    def _determine_tactic(self, event: NormalizedEvent, details: Dict[str, Any]) -> Tuple[MitreTactic, str, str]:
        """Maps an event and its anomaly details to MITRE ATT&CK tactic and technique."""
        # Check Exfiltration via USB
        if details.get("usb_exfiltration") or event.event_type in (EventType.USB_MOUNT, EventType.USB_TRANSFER):
            return (
                MitreTactic.EXFILTRATION,
                "T1052.001",
                "Exfiltration Over Physical Medium: Removable Drive"
            )

        # Check Impact / Ransomware
        if details.get("shadow_deletion") or event.event_type == EventType.ENCRYPTION_BURST:
            return (
                MitreTactic.IMPACT,
                "T1486",
                "Data Encrypted for Impact / Inhibit System Recovery"
            )

        # Check Defense Evasion / Log Clear
        if details.get("anti_forensics") or event.event_type == EventType.LOG_CLEAR:
            return (
                MitreTactic.DEFENSE_EVASION,
                "T1070.001",
                "Indicator Removal on Host: Clear Windows Event Logs"
            )

        # Check Credential Access
        if details.get("credential_dumping"):
            return (
                MitreTactic.CREDENTIAL_ACCESS,
                "T1003.001",
                "OS Credential Dumping: LSASS Memory"
            )

        # Check Collection
        if details.get("sensitive_file") or (event.event_type == EventType.FILE_ACCESS and details.get("sensitive_file")):
            return (
                MitreTactic.COLLECTION,
                "T1005",
                "Data from Local System / Network Staging"
            )

        # Check Lateral Movement
        if event.dest_host and event.source_host and event.dest_host.lower() != event.source_host.lower():
            return (
                MitreTactic.LATERAL_MOVEMENT,
                "T1021.002",
                "Remote Services: SMB/Windows Admin Shares"
            )

        # Check Execution
        if event.event_type == EventType.PROCESS_SPAWN or details.get("suspicious_command") or details.get("flagged_executable"):
            return (
                MitreTactic.EXECUTION,
                "T1059.001",
                "Command and Scripting Interpreter: PowerShell / Dual-use Binary"
            )

        # Initial Access
        if event.event_type in (EventType.AUTH_LOGIN, EventType.AUTH_FAILED) or details.get("external_ip"):
            return (
                MitreTactic.INITIAL_ACCESS,
                "T1078.002",
                "Valid Accounts: External / Unusual Domain Authentication"
            )

        return (MitreTactic.DISCOVERY, "T1087", "Account & System Discovery")

    def reconstruct_attack_chains(
        self,
        events: List[NormalizedEvent],
        graph_engine: ProvenanceGraphEngine
    ) -> List[Dict[str, Any]]:
        """
        Processes normalized events, scores them, suppresses isolated false alarms,
        and reconstructs verified multi-stage attack chains.
        """
        # Step 1: Score each event
        scored_events: List[Tuple[NormalizedEvent, float, List[str], Dict[str, Any]]] = []
        for evt in events:
            score, reasons, details = self.detector.evaluate_event(evt)
            scored_events.append((evt, score, reasons, details))

        # Filter candidates above minimal anomaly threshold (0.25)
        candidate_anomalies = [item for item in scored_events if item[1] >= 0.25]

        if not candidate_anomalies:
            return []

        # Step 2: Correlate across Graph entities & Temporal proximity
        # Group candidates by shared Actor User, Source/Dest Host, or IP
        clusters: List[List[Tuple[NormalizedEvent, float, List[str], Dict[str, Any]]]] = []

        for candidate in candidate_anomalies:
            evt = candidate[0]
            matched_cluster = None
            for cluster in clusters:
                # Check entity intersection
                cluster_users = {c[0].actor_user for c in cluster if c[0].actor_user}
                cluster_hosts = {c[0].source_host for c in cluster if c[0].source_host} | {c[0].dest_host for c in cluster if c[0].dest_host}
                cluster_ips = {c[0].source_ip for c in cluster if c[0].source_ip} | {c[0].dest_ip for c in cluster if c[0].dest_ip}

                has_user_overlap = evt.actor_user and evt.actor_user in cluster_users
                has_host_overlap = (evt.source_host and evt.source_host in cluster_hosts) or (evt.dest_host and evt.dest_host in cluster_hosts)
                has_ip_overlap = (evt.source_ip and evt.source_ip in cluster_ips) or (evt.dest_ip and evt.dest_ip in cluster_ips)

                if has_user_overlap or has_host_overlap or has_ip_overlap:
                    matched_cluster = cluster
                    break

            if matched_cluster is not None:
                matched_cluster.append(candidate)
            else:
                clusters.append([candidate])

        # Step 3: Enforce False Positive Suppression Rules
        # RULE: A genuine coordinated attack must span at least 2 distinct MITRE tactics
        # Step 3: Enforce False Positive Suppression Rules
        confirmed_attack_chains = []

        for cluster in clusters:
            # Sort cluster chronologically
            cluster.sort(key=lambda c: c[0].timestamp)

            stages: List[AttackStage] = []
            distinct_tactics: Set[MitreTactic] = set()
            suspicious_event_ids: Set[str] = set()
            stage_event_map: Dict[str, int] = {}
            actors: Set[str] = set()
            devices: Set[str] = set()
            ips: Set[str] = set()
            apps: Set[str] = set()

            for idx, (evt, score, reasons, details) in enumerate(cluster, start=1):
                tactic, tech_id, tech_name = self._determine_tactic(evt, details)
                distinct_tactics.add(tactic)
                suspicious_event_ids.add(evt.event_id)
                stage_event_map[evt.event_id] = idx

                if evt.actor_user:
                    actors.add(evt.actor_user)
                if evt.source_host:
                    devices.add(evt.source_host)
                if evt.dest_host:
                    devices.add(evt.dest_host)
                if evt.source_ip:
                    ips.add(evt.source_ip)
                if evt.dest_ip:
                    ips.add(evt.dest_ip)
                if evt.process_name:
                    apps.add(evt.process_name)

                # Supporting evidence extraction
                supporting: List[str] = []
                if evt.source_ip and details.get("external_ip"):
                    supporting.append(f"External origin IP: {evt.source_ip}")
                if details.get("off_hours_hour") is not None:
                    supporting.append(f"Off-hours temporal window ({details['off_hours_hour']:02d}:00 UTC)")
                if details.get("unusual_host"):
                    supporting.append(f"First-time host connection: {details['unusual_host']}")
                if details.get("flagged_executable"):
                    supporting.append(f"Offensive/dual-use executable: {details['flagged_executable']}")
                if details.get("suspicious_command"):
                    supporting.append(f"Suspicious command arguments: {details['suspicious_command']}")
                if details.get("sensitive_file"):
                    supporting.append(f"Confidential asset accessed: {details['sensitive_file']}")
                if details.get("usb_exfiltration"):
                    supporting.append(f"Removable storage serial: {details['usb_exfiltration']}")
                if details.get("anti_forensics"):
                    supporting.append("Security event log purged")
                if details.get("shadow_deletion"):
                    supporting.append("Volume Shadow Copy deletion detected")
                if details.get("credential_dumping"):
                    supporting.append("LSASS memory dumping activity")
                if not supporting and reasons:
                    supporting.extend(reasons)

                # Missing evidence extraction (expected kill-chain artifacts not observed)
                missing: List[str] = []
                if tactic == MitreTactic.INITIAL_ACCESS:
                    missing.append("No multi-factor authentication (MFA) bypass log observed")
                elif tactic == MitreTactic.EXECUTION:
                    missing.append("No persistent scheduled task or service registration confirmed")
                elif tactic == MitreTactic.COLLECTION:
                    missing.append("No file archival or compression utility observed")
                elif tactic == MitreTactic.EXFILTRATION:
                    missing.append("No outbound C2 network proxy session confirmed on host")
                elif tactic == MitreTactic.LATERAL_MOVEMENT:
                    missing.append("No Kerberos ticket-granting request anomaly recorded")

                # Contradicting evidence extraction (never fabricate)
                contradicting: List[str] = []
                if evt.source_ip and any(evt.source_ip.startswith(p) for p in ("10.", "192.168.", "172.16.", "127.0.0.1")):
                    contradicting.append("Source IP is within trusted corporate internal address space")
                if evt.actor_user and ("admin" in evt.actor_user.lower() or "backup" in evt.actor_user.lower()):
                    contradicting.append("User identity holds operational administrative/maintenance privileges")

                # Stage Status classification
                if score >= 0.35 and len(supporting) >= 1:
                    stage_status = "CONFIRMED"
                elif score >= 0.20:
                    stage_status = "PARTIAL"
                elif contradicting:
                    stage_status = "CONTRADICTED"
                else:
                    stage_status = "PARTIAL"

                # Formulate evidence proof with complete traceability
                justification_str = " | ".join(reasons) if reasons else "Anomalous entity interaction pattern"
                affected_ents = list({evt.actor_user, evt.dest_host, evt.source_host, evt.source_ip, evt.file_path, evt.device_id} - {None})

                evidence = AttackEvidence(
                    evidence_id=f"proof-stg-{idx}-{evt.event_id}",
                    event_id=evt.event_id,
                    timestamp=evt.timestamp,
                    log_source=evt.source,
                    raw_citation=evt.raw_log or f"Event {evt.event_id}: {evt.event_type.value}",
                    justification=justification_str,
                    confidence=min(0.98, max(0.60, round(score + 0.15, 2))),
                    indicators=list(details.keys()),
                    source_event=f"{evt.event_id} ({evt.source})",
                    entities=affected_ents,
                    supporting_evidence=supporting,
                    missing_evidence=missing,
                    contradicting_evidence=contradicting,
                    reason=justification_str
                )

                stage_name = f"Stage {idx}: {tech_name}"
                stage_desc = (
                    f"User '{evt.actor_user or 'N/A'}' engaged in {tactic.value} on "
                    f"host '{evt.dest_host or evt.source_host or 'N/A'}'. "
                    f"Evidence: {justification_str}"
                )

                stages.append(AttackStage(
                    stage_id=idx,
                    stage_name=stage_name,
                    tactic=tactic,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    timestamp=evt.timestamp,
                    actor=evt.actor_user or "Unknown Adversary",
                    affected_entities=affected_ents,
                    description=stage_desc,
                    proof=evidence,
                    risk_contribution=round(score * 25.0, 1),
                    status=stage_status,
                    mitre_technique=f"{tech_id}: {tech_name}",
                    source_event=f"{evt.event_id} ({evt.source})",
                    supporting_evidence=supporting,
                    missing_evidence=missing,
                    contradicting_evidence=contradicting
                ))

            # FALSE POSITIVE SUPPRESSION GATE:
            # Require at least 2 distinct tactics OR at least 3 chained actions
            chain_record = {
                "stages": stages,
                "actors": sorted(list(actors)),
                "devices": sorted(list(devices)),
                "ips": sorted(list(ips)),
                "apps": sorted(list(apps)),
                "tactics_count": len(distinct_tactics),
                "event_ids": suspicious_event_ids,
                "stage_event_map": stage_event_map
            }

            if len(distinct_tactics) >= 2 or len(stages) >= 3:
                # Mark nodes and edges in provenance graph with stage annotations
                graph_engine.mark_attack_subgraph(
                    suspicious_event_ids=suspicious_event_ids,
                    compromised_entities=actors | devices | ips | apps,
                    stage_event_map=stage_event_map
                )
                confirmed_attack_chains.append(chain_record)
            else:
                # Track as candidate for INSUFFICIENT_EVIDENCE
                self.unconfirmed_candidate_chains.append(chain_record)

        return confirmed_attack_chains
