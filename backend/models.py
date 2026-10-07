"""
Pydantic data models for AegisGraph-CTI
Defines normalized events, graph nodes/edges, attack stages, evidence proofs, and incidents.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class EventType(str, Enum):
    AUTH_LOGIN = "AUTH_LOGIN"
    AUTH_FAILED = "AUTH_FAILED"
    PROCESS_SPAWN = "PROCESS_SPAWN"
    FILE_ACCESS = "FILE_ACCESS"
    FILE_MODIFY = "FILE_MODIFY"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    USB_MOUNT = "USB_MOUNT"
    USB_TRANSFER = "USB_TRANSFER"
    PRIVILEGE_ESCALATE = "PRIVILEGE_ESCALATE"
    SERVICE_CREATE = "SERVICE_CREATE"
    LOG_CLEAR = "LOG_CLEAR"
    ENCRYPTION_BURST = "ENCRYPTION_BURST"


class MitreTactic(str, Enum):
    INITIAL_ACCESS = "TA0001: Initial Access"
    EXECUTION = "TA0002: Execution"
    PERSISTENCE = "TA0003: Persistence"
    PRIVILEGE_ESCALATION = "TA0004: Privilege Escalation"
    DEFENSE_EVASION = "TA0005: Defense Evasion"
    CREDENTIAL_ACCESS = "TA0006: Credential Access"
    DISCOVERY = "TA0007: Discovery"
    LATERAL_MOVEMENT = "TA0008: Lateral Movement"
    COLLECTION = "TA0009: Collection"
    EXFILTRATION = "TA0010: Exfiltration"
    IMPACT = "TA0040: Impact"


class NormalizedEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier or hash")
    timestamp: str = Field(..., description="ISO 8601 formatted timestamp")
    event_type: EventType = Field(..., description="Canonical event category")
    source: str = Field(..., description="Log source: WindowsEventLog, Syslog, Zeek, EDR, etc.")
    actor_user: Optional[str] = Field(None, description="Username or account associated")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    dest_ip: Optional[str] = Field(None, description="Destination IP address")
    source_host: Optional[str] = Field(None, description="Source device hostname")
    dest_host: Optional[str] = Field(None, description="Destination device hostname")
    process_name: Optional[str] = Field(None, description="Process executable name")
    process_command: Optional[str] = Field(None, description="Command line invocation")
    parent_process: Optional[str] = Field(None, description="Parent process name")
    file_path: Optional[str] = Field(None, description="Target file path")
    device_id: Optional[str] = Field(None, description="Peripheral device / USB serial")
    details: Dict[str, Any] = Field(default_factory=dict, description="Contextual metadata")
    raw_log: Optional[str] = Field(None, description="Original raw log string for proof citation")


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # "User", "Host", "IP", "Process", "File", "Device"
    is_compromised: bool = False
    risk_score: float = 0.0
    attributes: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str  # "LOGGED_INTO", "SPAWNED", "ACCESSED", "CONNECTED_TO", "COPIED_TO"
    timestamp: str
    event_id: str
    is_suspicious: bool = False
    tactic: Optional[str] = None


class AttackEvidence(BaseModel):
    evidence_id: str
    event_id: str
    timestamp: str
    log_source: str
    raw_citation: str
    justification: str
    confidence: float
    indicators: List[str]


class AttackStage(BaseModel):
    stage_id: int
    stage_name: str
    tactic: MitreTactic
    technique_id: str
    technique_name: str
    timestamp: str
    actor: str
    affected_entities: List[str]
    description: str
    proof: AttackEvidence
    risk_contribution: float


class MitigationAction(BaseModel):
    action_id: str
    priority: str  # "CRITICAL", "HIGH", "MEDIUM"
    category: str  # "CONTAINMENT", "ERADICATION", "RECOVERY"
    title: str
    description: str
    automated_command: Optional[str] = None
    target_entity: str


class IncidentReport(BaseModel):
    incident_id: str
    detected_at: str
    is_attack: bool
    verdict: str  # "MALICIOUS_ATTACK_CHAIN" or "BENIGN_BASELINE"
    confidence_score: float
    overall_risk_score: float
    risk_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"
    actors_involved: List[str]
    devices_involved: List[str]
    ips_involved: List[str]
    apps_involved: List[str]
    timeline: List[AttackStage]
    graph_nodes: List[GraphNode]
    graph_edges: List[GraphEdge]
    mitigations: List[MitigationAction]
    evidence_count: int
    summary_explanation: str
