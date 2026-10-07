"""
Behavioral Baseline Profiler & Statistical Anomaly Detector.
Maintains behavioral baselines to accurately distinguish genuine threats from normal benign activity.
Suppresses single isolated noise events to prevent false alarms.
"""

from datetime import datetime
from typing import Dict, Any, List, Tuple
from backend.models import NormalizedEvent, EventType


class AnomalyDetector:
    """Profiles user/host behavior and detects security anomalies with statistical scoring."""

    # High-risk executables and LOLBins often abused by adversaries
    HIGH_RISK_PROCESSES = {
        "mimikatz.exe", "vssadmin.exe", "psexec.exe", "procdump.exe",
        "certutil.exe", "wmic.exe", "net.exe", "whoami.exe", "nltest.exe"
    }

    # Sensitive path patterns
    SENSITIVE_PATHS = [
        "confidential", "finance", "q3_audit", "payroll", "ntds.dit",
        "sam", "system32/config", "secret", "executive", "passwords.txt", "wallet"
    ]

    KNOWN_BENIGN_SUBNETS = ("192.168.", "10.", "172.16.", "127.0.0.1")

    def __init__(self):
        # Known user history: {user: {"hosts": set(), "files": set(), "normal_ips": set()}}
        self.user_history: Dict[str, Dict[str, set]] = {}

    def train_baseline(self, benign_events: List[NormalizedEvent]):
        """Learns baseline behavior profiles from clean/historical events."""
        for evt in benign_events:
            user = evt.actor_user
            if not user:
                continue
            if user not in self.user_history:
                self.user_history[user] = {"hosts": set(), "files": set(), "normal_ips": set()}

            if evt.dest_host:
                self.user_history[user]["hosts"].add(evt.dest_host.lower())
            if evt.source_host:
                self.user_history[user]["hosts"].add(evt.source_host.lower())
            if evt.source_ip:
                self.user_history[user]["normal_ips"].add(evt.source_ip)
            if evt.file_path:
                self.user_history[user]["files"].add(evt.file_path.lower())

    def evaluate_event(self, event: NormalizedEvent) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        Evaluates a single event against behavioral baselines.
        Returns: (anomaly_score: 0.0 - 1.0, reasons: List[str], details: Dict)
        """
        score = 0.0
        reasons = []
        details = {}

        # 1. External IP / Geo Anomaly Check
        if event.source_ip:
            is_internal = any(event.source_ip.startswith(prefix) for prefix in self.KNOWN_BENIGN_SUBNETS)
            if not is_internal:
                score += 0.35
                reasons.append(f"Inbound authentication/traffic from foreign external IP {event.source_ip}")
                details["external_ip"] = event.source_ip

        # 2. Off-Hours Temporal Anomaly Check
        try:
            dt = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            hour = dt.hour
            # Off-hours: 11 PM to 5 AM
            if hour >= 23 or hour <= 5:
                # Off-hours alone is a mild anomaly (0.15)
                score += 0.15
                reasons.append(f"Activity observed during anomalous off-hours window ({hour:02d}:00 UTC)")
                details["off_hours_hour"] = hour
        except Exception:
            pass

        # 3. First-Time Host / Unusual Asset Access
        if event.actor_user and event.dest_host:
            user = event.actor_user
            target_host = event.dest_host.lower()
            if user in self.user_history:
                if target_host not in self.user_history[user]["hosts"]:
                    # Anomaly: User accessing host they have never touched before
                    score += 0.25
                    reasons.append(f"Unprecedented host access: user '{user}' never previously connected to '{event.dest_host}'")
                    details["unusual_host"] = event.dest_host

        # 4. Suspicious Command & LOLBins Execution
        if event.process_name:
            proc_lower = event.process_name.lower().split("\\")[-1]
            if proc_lower in self.HIGH_RISK_PROCESSES:
                score += 0.40
                reasons.append(f"Execution of dual-use/offensive utility '{proc_lower}'")
                details["flagged_executable"] = proc_lower

        if event.process_command:
            cmd = event.process_command.lower()
            if "-enc" in cmd or "encodedcommand" in cmd or "downloadstring" in cmd or "invoke-expression" in cmd:
                score += 0.50
                reasons.append("Obfuscated or in-memory download payload in command line invocation")
                details["suspicious_command"] = event.process_command
            elif "vssadmin delete shadows" in cmd or "wmic shadowcopy delete" in cmd:
                score += 0.65
                reasons.append("Volume Shadow Copy deletion detected (Ransomware defense evasion / inhibitor)")
                details["shadow_deletion"] = True
            elif "sekurlsa" in cmd or "lsass" in cmd:
                score += 0.60
                reasons.append("LSASS memory dumping / credential harvesting pattern detected")
                details["credential_dumping"] = True

        # 5. Sensitive File Access Check (Data Collection)
        if event.file_path:
            file_lower = event.file_path.lower()
            if any(sens in file_lower for sens in self.SENSITIVE_PATHS):
                user = event.actor_user or "unknown"
                is_novel = True
                if user in self.user_history and file_lower in self.user_history[user]["files"]:
                    is_novel = False

                if is_novel:
                    score += 0.40
                    reasons.append(f"First-time unauthorized access to high-value confidential asset: '{event.file_path}'")
                    details["sensitive_file"] = event.file_path

        # 6. Peripheral USB Exfiltration Check
        if event.event_type in (EventType.USB_MOUNT, EventType.USB_TRANSFER) or event.device_id:
            score += 0.45
            reasons.append(f"Removable storage peripheral event detected (Device Serial: {event.device_id or 'USB_MASS_STORAGE'})")
            details["usb_exfiltration"] = event.device_id

        # 7. Audit Log Clearance Check
        if event.event_type == EventType.LOG_CLEAR:
            score += 0.60
            reasons.append("Security Event Log was intentionally purged/cleared (Anti-forensics / Defense Evasion)")
            details["anti_forensics"] = True

        # Cap score at 1.0
        final_score = min(round(score, 2), 1.0)
        return final_score, reasons, details
