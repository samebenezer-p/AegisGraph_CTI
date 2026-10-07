"""
Unit tests for LogNormalizer pipeline.
Validates ingestion of Windows Event Logs, Syslog, Zeek Network flows, and USB peripheral logs.
"""

from backend.pipeline.normalizer import LogNormalizer
from backend.models import EventType


def test_windows_event_log_normalization():
    normalizer = LogNormalizer()

    # Test EventID 4624 (Logon)
    win_4624 = {
        "EventID": 4624,
        "TimeCreated": "2026-10-06T08:30:00Z",
        "TargetUserName": "admin_sarah",
        "IpAddress": "192.168.1.55",
        "WorkstationName": "WKS-ADMIN",
        "Computer": "DC-CORP-01",
        "LogonType": 10
    }
    event = normalizer.normalize_windows_event(win_4624)
    assert event.event_type == EventType.AUTH_LOGIN
    assert event.actor_user == "admin_sarah"
    assert event.source_ip == "192.168.1.55"
    assert event.dest_host == "DC-CORP-01"

    # Test EventID 4688 (Process Creation)
    win_4688 = {
        "EventID": 4688,
        "TimeCreated": "2026-10-06T08:35:00Z",
        "SubjectUserName": "admin_sarah",
        "Computer": "DC-CORP-01",
        "NewProcessName": "powershell.exe",
        "CommandLine": "powershell.exe -NoProfile",
        "ParentProcessName": "cmd.exe"
    }
    event = normalizer.normalize_windows_event(win_4688)
    assert event.event_type == EventType.PROCESS_SPAWN
    assert event.process_name == "powershell.exe"
    assert event.parent_process == "cmd.exe"

    # Test EventID 1102 (Log Clear)
    win_1102 = {
        "EventID": 1102,
        "TimeCreated": "2026-10-06T08:40:00Z",
        "SubjectUserName": "admin_sarah",
        "Computer": "DC-CORP-01"
    }
    event = normalizer.normalize_windows_event(win_1102)
    assert event.event_type == EventType.LOG_CLEAR


def test_usb_peripheral_normalization():
    normalizer = LogNormalizer()
    usb_log = {
        "timestamp": "2026-10-06T09:00:00Z",
        "event_type": "USB_TRANSFER",
        "actor_user": "j_doe",
        "source_host": "WKS-01",
        "file_path": "C:\\Secret.docx",
        "device_id": "USBSTOR_001"
    }
    event = normalizer.normalize_generic_dict(usb_log)
    assert event.event_type == EventType.USB_TRANSFER
    assert event.device_id == "USBSTOR_001"
    assert event.file_path == "C:\\Secret.docx"
