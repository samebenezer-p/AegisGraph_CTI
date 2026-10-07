"""
Data Pipeline Normalizer: Converts raw heterogeneous logs into unified canonical events.
Supports Windows Event Logs, Linux Syslog/Auditd, Network/Zeek logs, and Endpoint/USB logs.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Union
from backend.models import NormalizedEvent, EventType


class LogNormalizer:
    """Normalizes heterogeneous security logs into canonical NormalizedEvent instances."""

    @staticmethod
    def generate_event_id(content: str, timestamp: str) -> str:
        """Deterministically generates a unique event hash."""
        seed = f"{timestamp}_{content}"
        return f"evt-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"

    @classmethod
    def normalize_generic_dict(cls, data: Dict[str, Any]) -> NormalizedEvent:
        """Parses a dictionary that may already follow canonical or semi-canonical structure."""
        timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
        raw_str = data.get("raw_log") or json.dumps(data)
        event_id = data.get("event_id") or cls.generate_event_id(raw_str, timestamp)

        # Detect or map EventType
        raw_type = str(data.get("event_type", "")).upper()
        event_type = EventType.AUTH_LOGIN
        for candidate in EventType:
            if candidate.value == raw_type:
                event_type = candidate
                break
        else:
            # Fallback heuristic mapping
            if "LOGIN" in raw_type or "AUTH" in raw_type:
                event_type = EventType.AUTH_LOGIN
            elif "PROCESS" in raw_type or "EXEC" in raw_type:
                event_type = EventType.PROCESS_SPAWN
            elif "FILE" in raw_type and ("MODIFY" in raw_type or "WRITE" in raw_type):
                event_type = EventType.FILE_MODIFY
            elif "FILE" in raw_type:
                event_type = EventType.FILE_ACCESS
            elif "USB" in raw_type and "TRANSFER" in raw_type:
                event_type = EventType.USB_TRANSFER
            elif "USB" in raw_type:
                event_type = EventType.USB_MOUNT
            elif "NET" in raw_type or "FLOW" in raw_type:
                event_type = EventType.NETWORK_CONNECT
            elif "SERVICE" in raw_type:
                event_type = EventType.SERVICE_CREATE
            elif "CLEAR" in raw_type:
                event_type = EventType.LOG_CLEAR

        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            source=data.get("source", "EnterpriseLogPipeline"),
            actor_user=data.get("actor_user") or data.get("user") or data.get("username"),
            source_ip=data.get("source_ip") or data.get("src_ip"),
            dest_ip=data.get("dest_ip") or data.get("dst_ip"),
            source_host=data.get("source_host") or data.get("hostname") or data.get("host"),
            dest_host=data.get("dest_host") or data.get("target_host"),
            process_name=data.get("process_name") or data.get("image") or data.get("app"),
            process_command=data.get("process_command") or data.get("cmdline") or data.get("command"),
            parent_process=data.get("parent_process"),
            file_path=data.get("file_path") or data.get("target_file"),
            device_id=data.get("device_id") or data.get("usb_serial"),
            details=data.get("details", {}),
            raw_log=raw_str
        )

    @classmethod
    def normalize_windows_event(cls, win_event: Dict[str, Any]) -> NormalizedEvent:
        """Parses Windows Event Log format (e.g. 4624, 4688, 4663, 7045, 1102)."""
        event_code = win_event.get("EventID") or win_event.get("event_id")
        timestamp = win_event.get("TimeCreated") or datetime.now(timezone.utc).isoformat()
        raw_log = json.dumps(win_event)
        evt_id = cls.generate_event_id(raw_log, timestamp)

        if event_code in (4624, "4624"):
            return NormalizedEvent(
                event_id=evt_id,
                timestamp=timestamp,
                event_type=EventType.AUTH_LOGIN,
                source="Windows-Security-4624",
                actor_user=win_event.get("TargetUserName"),
                source_ip=win_event.get("IpAddress"),
                source_host=win_event.get("WorkstationName"),
                dest_host=win_event.get("Computer"),
                details={"LogonType": win_event.get("LogonType"), "AuthenticationPackage": win_event.get("AuthenticationPackageName")},
                raw_log=raw_log
            )
        elif event_code in (4688, "4688"):
            return NormalizedEvent(
                event_id=evt_id,
                timestamp=timestamp,
                event_type=EventType.PROCESS_SPAWN,
                source="Windows-Security-4688",
                actor_user=win_event.get("SubjectUserName"),
                source_host=win_event.get("Computer"),
                process_name=win_event.get("NewProcessName"),
                process_command=win_event.get("CommandLine"),
                parent_process=win_event.get("ParentProcessName"),
                details={"TokenElevationType": win_event.get("TokenElevationType")},
                raw_log=raw_log
            )
        elif event_code in (4663, "4663"):
            return NormalizedEvent(
                event_id=evt_id,
                timestamp=timestamp,
                event_type=EventType.FILE_ACCESS,
                source="Windows-Security-4663",
                actor_user=win_event.get("SubjectUserName"),
                source_host=win_event.get("Computer"),
                file_path=win_event.get("ObjectName"),
                process_name=win_event.get("ProcessName"),
                details={"AccessMask": win_event.get("AccessMask")},
                raw_log=raw_log
            )
        elif event_code in (1102, "1102"):
            return NormalizedEvent(
                event_id=evt_id,
                timestamp=timestamp,
                event_type=EventType.LOG_CLEAR,
                source="Windows-Security-1102",
                actor_user=win_event.get("SubjectUserName"),
                source_host=win_event.get("Computer"),
                details={"Message": "The audit log was cleared"},
                raw_log=raw_log
            )
        else:
            return cls.normalize_generic_dict(win_event)

    @classmethod
    def ingest_records(cls, raw_records: Union[List[Dict[str, Any]], str]) -> List[NormalizedEvent]:
        """Ingests a list of raw records or a JSON string and returns NormalizedEvents."""
        if isinstance(raw_records, str):
            raw_records = json.loads(raw_records)

        events = []
        for record in raw_records:
            if "EventID" in record:
                events.append(cls.normalize_windows_event(record))
            else:
                events.append(cls.normalize_generic_dict(record))

        # Sort chronologically
        events.sort(key=lambda e: e.timestamp)
        return events
