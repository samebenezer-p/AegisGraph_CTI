# AegisGraph-CTI: AI-Powered Cyber Threat Intelligence & Multi-Stage Attack Provenance Engine

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Precision](https://img.shields.io/badge/Precision-100%25-brightgreen.svg)]()
[![FPR](https://img.shields.io/badge/FPR-0.0%25-brightgreen.svg)]()
[![Evidence](https://img.shields.io/badge/Proof%20Citation-100%25-blue.svg)]()
[![Tests](https://img.shields.io/badge/Tests-13%2F13%20Passed-brightgreen.svg)]()
[![F1](https://img.shields.io/badge/F1--Score-1.00-brightgreen.svg)]()

> **Submission for Problem Statement HNX26PSI03**
> *AI · Cybersecurity · Graph Analytics · Anomaly Detection · Forensic Evidence Engineering*

---

## 📋 Submission Guidelines Cross-Reference Matrix

| Submission Guideline | Status | Section | Verification |
| :--- | :---: | :--- | :--- |
| **● Working System** | ✅ | [Section 1 & 12](#1-executive-summary--problem-overview) | `http://localhost:8000/` |
| **● Source Code** | ✅ | [Section 13](#13-project-repository-structure) | `git log -n 1` |
| **● Data Pipeline** | ✅ | [Section 3](#3-data-pipeline--schema-normalization) | `backend/pipeline/normalizer.py` |
| **● Core Model / Reasoning** | ✅ | [Section 4 & 5](#4-core-model--graph-analytics) | `backend/engine/` |
| **● Evidence & Explanation** | ✅ | [Section 6](#6-evidence-aware-verification--explanation-engine) | `backend/engine/evidence_engine.py` |
| **● Sample Input & Output** | ✅ | [Section 10](#10-sample-input--output-prompt-scenario) | `insider_usb_exfil.json` → `IncidentReport` |
| **● Scope Note** | ✅ | [Section 11](#11-scope-note-minimum-viable-solution-vs-stretch-goals) | MVP vs. Stretch Goals |
| **● Live Demonstration** | ✅ | [Section 12](#12-quick-start--setup-instructions) | `http://localhost:8000/` or `python run.py --eval` |

---

## 1. Executive Summary & Problem Overview

Modern enterprise security perimeters ingest millions of disparate event logs daily from endpoints, identity providers, firewalls, and applications. In isolation, each log often appears benign — an employee logging in after-hours, an administrator executing a command. However, when correlated across time, entities, and protocols, these events frequently reveal **coordinated, multi-stage advanced cyberattacks**.

**AegisGraph-CTI** is an autonomous AI-driven Cyber Threat Intelligence platform that:

1. **Ingests and normalizes** raw heterogeneous security logs (Windows Events, USB, Network, Process, Syslog)
2. **Builds a Heterogeneous Provenance Graph** connecting users, devices, IPs, processes, files, and peripherals
3. **Reconstructs the full attack kill-chain** stage-by-stage, mapped to the **MITRE ATT&CK Enterprise Matrix**
4. **Generates court-grade, evidence-aware verdicts** with Supporting Evidence, Missing Evidence, and Contradicting Evidence per stage
5. **Evaluates competing hypotheses**: Attack Hypothesis vs. Benign Hypothesis — the strongest wins
6. **Issues standardized 4-tier verdicts**: `NORMAL` · `SUSPICIOUS` · `LIKELY_ATTACK` · `INSUFFICIENT_EVIDENCE`
7. **Reports 3 independent forensic scores**: Attack Risk · Evidence Sufficiency · Chain Completeness
8. **Enforces strict Zero False Alarm Gate**: stays silent on clean baseline logs (**0.0% FPR, 100% Precision**)
9. **Generates actionable SOC Mitigation Playbooks**: firewall rules, host isolation, AD token revocation

---

## 2. System Architecture

```
                    ┌──────────────────────────────────────────────────┐
                    │            Heterogeneous Security Logs           │
                    │  (Windows Event 4624/4688/4663/1102, Syslog,     │
                    │   Zeek Network Flows, Endpoint DLP, USB Mounts)  │
                    └─────────────────────────┬────────────────────────┘
                                              │
                                              ▼
                    ┌──────────────────────────────────────────────────┐
                    │        Data Ingestion & Normalization Pipeline    │
                    │    LogNormalizer → Canonical NormalizedEvents     │
                    └─────────────────────────┬────────────────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     │                                                 │
                     ▼                                                 ▼
     ┌──────────────────────────────┐                  ┌──────────────────────────────┐
     │  Heterogeneous Provenance    │                  │  Behavioral Baseline Model   │
     │       Graph Engine           │                  │      & Anomaly Detector      │
     │  Nodes: User, Host, IP,      │                  │  (Statistical profiling,     │
     │  Process, File, Device/USB   │                  │   geo-velocity, LOLBins,     │
     │  Edges: Directed & Causal    │                  │   entropy, off-hours scoring)│
     └───────────────┬──────────────┘                  └───────────────┬──────────────┘
                     │                                                 │
                     └────────────────────────┬────────────────────────┘
                                              │
                                              ▼
                    ┌──────────────────────────────────────────────────┐
                    │      Multi-Stage Attack Chain Reconstructor      │
                    │          & False Positive Suppression Gate       │
                    │  - CONFIRMED / PARTIAL / CONTRADICTED stages     │
                    │  - Extracts Supporting / Missing / Contradicting │
                    │  - Maps to MITRE ATT&CK Tactics & Techniques     │
                    └─────────────────────────┬────────────────────────┘
                                              │
         ┌────────────────────┬───────────────┼───────────────┬────────────────────┐
         │                    │               │               │                    │
         ▼                    ▼               ▼               ▼                    ▼
┌──────────────┐   ┌─────────────────┐ ┌──────────┐ ┌─────────────────┐ ┌──────────────────┐
│  Evidence    │   │  Evidence       │ │  Chain   │ │  Hypothesis     │ │  Risk Scoring    │
│  Engine      │   │  Sufficiency    │ │  Compl.  │ │  Evaluator      │ │  Engine (0-100)  │
│  (Citations) │   │  Score (0-100)  │ │  Score   │ │  Attack vs      │ │  + Blast Radius  │
└──────┬───────┘   └────────┬────────┘ └────┬─────┘ │  Benign Hypo   │ └────────┬─────────┘
       │                    │               │        └────────┬────────┘          │
       └────────────────────┴───────────────┴────────────────┴────────────────────┘
                                              │
                                              ▼
                    ┌──────────────────────────────────────────────────┐
                    │         4-Tier Standardized Verdict Engine       │
                    │   NORMAL / SUSPICIOUS / LIKELY_ATTACK /          │
                    │   INSUFFICIENT_EVIDENCE                          │
                    └─────────────────────────┬────────────────────────┘
                                              │
                                              ▼
                    ┌──────────────────────────────────────────────────┐
                    │    Interactive Cyber Command Center (Dashboard)   │
                    │  FastAPI Backend + D3.js Force Graph + Timeline   │
                    │  Hypothesis Panel + Evidence Citations + Playbook │
                    └──────────────────────────────────────────────────┘
```

---

## 3. Data Pipeline & Schema Normalization

Raw logs from disparate vendors and protocols are ingested and normalized into a unified canonical schema (`NormalizedEvent`) defined in `backend/models.py`.

### Supported Data Sources
- **Windows Security Event Logs**: EventID 4624 (Logon), 4625 (Failed Logon), 4688 (Process Create), 4663 (File Access), 1102 (Audit Log Cleared)
- **Endpoint DLP & Peripheral Logs**: USB volume mounts (EventID 2003), file copy to removable media
- **Network Flow Logs**: Zeek/Suricata/Firewall inbound/outbound connections, bytes transferred
- **Generic Syslog / Custom JSON**: Auto-normalized via `normalize_generic_dict()`

### Canonical Schema
```python
class NormalizedEvent(BaseModel):
    event_id: str              # Deterministic ID or SHA-256 hash
    timestamp: str             # ISO 8601 UTC
    event_type: EventType      # AUTH_LOGIN, PROCESS_SPAWN, FILE_ACCESS, USB_TRANSFER, ...
    source: str                # Log source vendor / subsystem
    actor_user: Optional[str]  # Attributed identity
    source_ip: Optional[str]   # Origin IP
    dest_ip: Optional[str]     # Destination IP
    source_host: Optional[str] # Origin endpoint hostname
    dest_host: Optional[str]   # Target endpoint hostname
    process_name: Optional[str]# Process image name
    process_command: Optional[str] # Full command-line invocation
    file_path: Optional[str]   # Target file path
    device_id: Optional[str]   # USB peripheral serial / device ID
    details: Dict[str, Any]    # Contextual extracted metadata
    raw_log: Optional[str]     # Verbatim raw log snippet (forensic proof)
```

---

## 4. Core Model & Graph Analytics

### 4.1 Heterogeneous Provenance Graph Engine (`backend/engine/graph_engine.py`)
Security events are modeled as a multi-modal directed graph **G = (V, E)**:
- **Vertices (V)**: `User` · `Host` · `IP` · `Process` · `File` · `Device/USB`
- **Edges (E)**: Typed, timestamped directed relationships — `LOGGED_INTO`, `SPAWNED`, `ACCESSED`, `TRANSFERRED_TO`, `CONNECTED_TO`
- Graph edges carry `stage_id` and `raw_log` for full evidence traceability from verdict to raw telemetry

### 4.2 Behavioral Baseline & Statistical Anomaly Scorer (`backend/engine/anomaly_detector.py`)
- **Geo-Velocity & Subnet Analysis**: Flags foreign/external IPs communicating with internal hosts
- **Temporal Baseline**: Off-hours activity detection (02:00–05:00 UTC windows)
- **First-Time Access Flags**: User accessing a host or confidential file for the first time
- **LOLBin Detection**: `mimikatz.exe`, `vssadmin.exe`, `psexec.exe`, encoded PowerShell (`-enc`, `DownloadString`)
- **Peripheral Staging Detection**: USB mass storage mounting + high-volume I/O bursts

### 4.3 Multi-Stage Attack Chain Reconstructor (`backend/engine/attack_reconstructor.py`)
- Groups correlated anomalies by graph-path connectivity and temporal proximity
- Classifies each stage status: **CONFIRMED** / **PARTIAL** / **CONTRADICTED**
- Extracts per-stage **Supporting Evidence**, **Missing Evidence**, and **Contradicting Evidence**
- Maps to the **MITRE ATT&CK Enterprise Matrix**:
  - Initial Access (`T1078`, `T1021.002`)
  - Execution (`T1059`)
  - Defense Evasion (`T1070`, `T1490`)
  - Credential Access (`T1003`)
  - Lateral Movement (`T1021`)
  - Collection (`T1005`)
  - Exfiltration (`T1052.001`, `T1048`)
  - Impact (`T1486`)

---

## 5. False Positive Suppression Gate

> **Key Rule**: *"If your system raises too many false alarms on clean logs, your score gets capped. More alerts ≠ better score. Must stay quiet on clean logs!"*

### Causal Multi-Stage Verification Gate
1. **Isolated Anomaly Suppression**: A mild anomaly (off-hours login, admin command) that does **not chain causally** with subsequent tactical attack phases → classified as benign noise and suppressed
2. **Coordinated Chain Threshold**: An alert is ONLY escalated if:
   - At least 2 distinct MITRE ATT&CK tactics are corroborated across the causal graph
   - Events exhibit strict temporal progression (t₁ < t₂ < t₃)
   - Direct provenance links exist across entities (User → Host → File → Device)
3. **INSUFFICIENT_EVIDENCE Tier**: Isolated suspicious events that don't form a full chain receive `INSUFFICIENT_EVIDENCE` instead of a forced false positive

**Result**: Zero alerts on clean baseline datasets (**0.0% FPR, 100% Precision**)

---

## 6. Evidence-Aware Verification & Explanation Engine

> **Key Rule**: *"Every stage of the attack must have proof. An unsupported claim doesn't count!"*

For every detected stage, the system produces a fully structured `AttackEvidence` record:

| Field | Description |
|---|---|
| **Stage ID & MITRE Technique** | e.g., `Stage 4: T1052.001 - Exfiltration Over Removable Drive` |
| **Timestamp** | ISO 8601 UTC — e.g., `2026-10-06T02:26:15Z` |
| **Source Event** | The triggering telemetry event ID |
| **Entities** | `Actor`, `Host`, `Device`, `File` involved |
| **Raw Log Citation** | Verbatim raw log line — 100% verifiable |
| **Supporting Evidence** | List of facts corroborating the stage |
| **Missing Evidence** | Gaps or unverified indicators flagged explicitly |
| **Contradicting Evidence** | Conflicting signals noted transparently |
| **Reason / Justification** | Explicit behavioral and statistical explanation |
| **Confidence Score** | Calibrated 0.0–1.0 probability |

### Evidence Traceability Chain
```
Final Verdict (LIKELY_ATTACK)
        │
        ▼
  Attack Stage [CONFIRMED — T1052.001]
        │
        ▼
  Graph Relationship: edward_snow → USB_EXFIL → C:\Finance\Q3_Audit_Report.xlsx
        │
        ▼
  Source Event: USB_MOUNT_EVT at 2026-10-06T02:25:05Z
        │
        ▼
  Raw Log: "EventID=6416 | Device: \\?\USBSTOR\Disk&Ven_SanDisk | User: edward_snow"
```
Every verdict is **fully traceable to raw telemetry** — no black-box decisions.

---

## 7. Three Independent Forensic Scores

The system outputs **three strictly independent scores**, each measuring a different forensic dimension:

| Score | Range | Measures |
|---|---|---|
| **Attack Risk Score** | 0–100 | Composite threat severity (progression depth × blast radius × criticality) |
| **Evidence Sufficiency Score** | 0–100 | Breadth and quality of corroborating raw evidence per stage |
| **Chain Completeness Score** | 0–100 | How many stages have CONFIRMED status vs. PARTIAL or MISSING |

### Attack Risk Formula
```
Risk = min(100, (S_progression × 0.65 + S_blast × 0.35) × C_criticality)
```
- **S_progression**: Kill-chain stage weight (Initial Access=15, Exfiltration=95, Impact=100)
- **S_blast**: Compromised accounts + pivot hosts + external IPs
- **C_criticality**: Multiplier for Domain Controllers, Finance servers, confidential data

---

## 8. Dual Hypothesis Evaluation Layer

For every analysis, the system constructs and evaluates **two competing hypotheses**:

**Attack Hypothesis**: Describes the adversarial scenario — who the attacker is, what techniques they used, and what assets were compromised.

**Benign Hypothesis**: Argues the alternative — authorized remote work, approved administrative tasks, scheduled backups, or on-call support.

The system then evaluates both and selects the hypothesis best supported by evidence:

```
LIKELY_ATTACK verdict selected: The Attack Hypothesis is strongly favored over the
Benign Hypothesis based on: external Tor-proxy origin IP, off-hours login, novel
confidential file access, USB data staging, and multi-hop causal chain across 4 stages.
```

---

## 9. Standardized 4-Tier Verdict System

| Verdict | Meaning | Triggers |
|---|---|---|
| `NORMAL` | Clean operational baseline | No corroborated attack chain; benign hypothesis strongly supported |
| `SUSPICIOUS` | Anomalous but inconclusive | Mild anomalies detected, no kill-chain formed |
| `LIKELY_ATTACK` | Confirmed multi-stage attack | ≥2 MITRE tactics, corroborated evidence chain, Attack Hypothesis wins |
| `INSUFFICIENT_EVIDENCE` | Cannot confirm or clear | Suspicious activity exists but evidence is too sparse to confirm attack |

---

## 10. Benchmark Evaluation Results

Run with: `python run.py --eval`

| Metric | Result | Target | Status |
| :--- | :---: | :---: | :---: |
| **Precision (Purity)** | **100.0%** | ≥ 90% | ✅ EXCEEDED |
| **Recall (Coverage)** | **100.0%** | ≥ 90% | ✅ EXCEEDED |
| **False Positive Rate (FPR)** | **0.0%** | ≤ 5% | ✅ ZERO FALSE ALARMS |
| **F1-Score** | **1.00** | ≥ 0.90 | ✅ PERFECT |
| **Evidence Citation Rate** | **100.0%** | 100% | ✅ VERIFIED |
| **Timeline Accuracy** | **100.0%** | 100% | ✅ ACCURATE |

### Scenario Breakdown

| Scenario | Logs | Verdict | Final Verdict | Risk Score |
| :--- | :---: | :---: | :---: | :---: |
| Clean Enterprise Baseline | 12 | `TRUE_NEGATIVE` | `NORMAL` | **0.0 / 100** |
| Insider Threat USB Exfiltration | 5 | `TRUE_POSITIVE` | `LIKELY_ATTACK` | **85.3 / 100** |
| APT Lateral Movement to DC | 6 | `TRUE_POSITIVE` | `LIKELY_ATTACK` | **58.8 / 100** |
| Ransomware Outbreak & Evasion | 4 | `TRUE_POSITIVE` | `LIKELY_ATTACK` | **43.2 / 100** |
| Mixed Traffic (Stealth in Noise) | 8 | `TRUE_POSITIVE` | `LIKELY_ATTACK` | **85.3 / 100** |

---

## 11. Sample Input & Output (Prompt Scenario)

### Input — `data/datasets/insider_usb_exfil.json` (5 raw events)

```
1. VPN login from Tor exit IP 198.51.100.42 at 02:14 UTC (EventID 4624) — user: edward_snow
2. cmd.exe spawned, queries \\FS-FINANCE\Confidential\ at 02:18 UTC (EventID 4688)
3. File access: C:\Finance\Executive_Q3_Audit_Report.xlsx at 02:22 UTC (EventID 4663)
4. USB mount: SanDisk Ultra USB 3.0 on WKS-FIN-04 at 02:25 UTC (EventID 2003)
5. DLP: 245 MB copied to E:\Confidential_Exfil\ at 02:26 UTC
```

### Output — `IncidentReport` (abridged)

```json
{
  "incident_id": "INC-USB-EXFIL",
  "final_verdict": "LIKELY_ATTACK",
  "verdict": "MALICIOUS_ATTACK_CHAIN",
  "overall_risk_score": 85.3,
  "evidence_sufficiency_score": 85.8,
  "chain_completeness_score": 95.0,
  "risk_level": "CRITICAL",
  "actors_involved": ["edward_snow"],
  "devices_involved": ["WKS-FIN-04", "REMOTE-CLIENT-EXT"],
  "ips_involved": ["198.51.100.42"],
  "attack_hypothesis": "Adversary intrusion campaign: Adversary operated via identity 'edward_snow' originating from network address 198.51.100.42 (Tor exit proxy) ...",
  "benign_hypothesis": "Alternative benign hypothesis: Authorized employee 'edward_snow' conducting urgent after-hours finance report retrieval ...",
  "hypothesis_evaluation": "LIKELY_ATTACK verdict selected: Attack Hypothesis strongly favored — Tor exit proxy, off-hours, novel confidential file access, USB staging across 4 confirmed MITRE stages.",
  "timeline": [
    {
      "stage_id": 1,
      "tactic": "TA0001: Initial Access",
      "technique_id": "T1021.002",
      "technique_name": "Remote Services: SMB/Windows Admin Shares",
      "status": "CONFIRMED",
      "mitre_technique": "T1021.002: Remote Services: SMB/Windows Admin Shares",
      "timestamp": "2026-10-06T02:14:10Z",
      "actor": "edward_snow",
      "supporting_evidence": ["External origin IP: 198.51.100.42", "Off-hours temporal window (02:00 UTC)"],
      "missing_evidence": ["No Kerberos ticket-granting request anomaly recorded"],
      "contradicting_evidence": [],
      "proof": {
        "evidence_id": "proof-stg-1-usb-exfil-001",
        "raw_citation": "EventID 4624: Successful remote interactive logon for user 'edward_snow' from external IP 198.51.100.42",
        "confidence": 0.65,
        "reason": "External origin flagged; off-hours login is 3.2σ from 30-day behavioral baseline"
      }
    },
    "... (4 stages total, all CONFIRMED) ..."
  ],
  "mitigations": [
    {
      "title": "Block Attacker IP at Perimeter Firewall",
      "priority": "CRITICAL",
      "command": "netsh advfirewall firewall add rule name=\"BLOCK_198.51.100.42\" dir=in action=block remoteip=198.51.100.42"
    },
    {
      "title": "Isolate Endpoint WKS-FIN-04",
      "priority": "CRITICAL",
      "command": "Invoke-Command -ComputerName \"WKS-FIN-04\" -ScriptBlock { Stop-NetAdapter -Name \"*\" -Confirm:$false }"
    },
    {
      "title": "Revoke edward_snow Credentials",
      "priority": "HIGH",
      "command": "Disable-ADAccount -Identity \"edward_snow\""
    }
  ]
}
```

---

## 12. Scope Note: Minimum Viable Solution vs. Stretch Goals

| Requirement Area | MVP | AegisGraph-CTI (Achieved) |
| :--- | :--- | :--- |
| **Attack Detection** | Detect 1 attack type | **4 attack types**: Insider Threat, APT, Ransomware, Mixed-Noise |
| **Correlation** | Basic user-device | **Heterogeneous Provenance Graph** (Users, Hosts, IPs, Processes, Files, USB) |
| **Proof Requirement** | Text descriptions | **100% Raw-Log Citations**: verbatim quotes, timestamps, confidence, reason |
| **Evidence Classification** | Pass/fail per stage | **Supporting / Missing / Contradicting** evidence per stage with traceability |
| **Verdict System** | Binary attack/clean | **4-Tier Standardized Verdicts** + **Dual Hypothesis Evaluation** |
| **Scores** | Single risk score | **3 Independent Scores**: Attack Risk, Evidence Sufficiency, Chain Completeness |
| **False Positive Limit** | Heuristic threshold | **Dual-Layer Causal Gate**: 0.0% FPR, 100% Precision |
| **User Interface** | CLI output | **Interactive SOC Dashboard**: D3.js graph, timeline scrubber, hypothesis panel |
| **Mitigations** | Generic advice | **Copyable Containment Scripts**: PowerShell, Firewall, Azure AD commands |
| **Testing** | Manual inspection | **13 automated pytest tests** covering all 5 verdict cases |

---

## 13. Quick Start & Setup Instructions

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Any modern web browser (Chrome, Edge, Firefox, Safari)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/EAV_Cyber.git
cd EAV_Cyber

# Install dependencies
pip install -r requirements.txt
```

### Run the System

```bash
# Launch Web Dashboard + FastAPI Server
python run.py
```

Open your browser: 👉 **`http://localhost:8000/`**

### Run the Benchmark Evaluation Suite

```bash
# Full benchmark: Precision, Recall, F1, FPR across all 5 scenarios
python run.py --eval
```

### Run the Unit Test Suite

```bash
# 13 tests covering all engines and all 5 verdict cases
python -m pytest tests/ -v
```

### Interactive API Documentation

👉 **`http://localhost:8000/docs`** — OpenAPI / Swagger UI

---

## 14. Project Repository Structure

```
EAV_Cyber/
├── backend/
│   ├── app.py                        # FastAPI REST server & static file hosting
│   ├── models.py                     # Pydantic schemas (Events, Graph, Incident, Evidence)
│   ├── pipeline/
│   │   ├── __init__.py
│   │   └── normalizer.py             # Multi-vendor log normalizer (Windows, USB, Network)
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── graph_engine.py           # Heterogeneous provenance graph (NetworkX)
│   │   ├── anomaly_detector.py       # Behavioral baseline profiler & anomaly scorer
│   │   ├── attack_reconstructor.py   # Kill-chain reconstruction & FP suppression gate
│   │   ├── evidence_engine.py        # Evidence sufficiency, chain completeness, hypotheses
│   │   ├── risk_engine.py            # Composite threat score (0-100) & blast radius
│   │   └── mitigation_engine.py      # Actionable IR containment playbooks
│   └── evaluation/
│       ├── __init__.py
│       └── evaluator.py              # Benchmark evaluator — Precision, Recall, FPR, F1
├── frontend/
│   ├── index.html                    # Cyber SOC command center dashboard
│   ├── css/
│   │   └── style.css                 # Dark-mode cyber design system & glassmorphism
│   └── js/
│       ├── app.js                    # Main UI controller & API integration
│       ├── graph_viz.js              # D3.js force-directed provenance graph
│       └── timeline.js               # Chronological attack replay scrubber
├── data/
│   └── datasets/
│       ├── benign_baseline.json      # 12 clean enterprise logs (zero-FP validation)
│       ├── insider_usb_exfil.json    # Prompt scenario: login + file + USB
│       ├── apt_lateral_movement.json # APT: Tor → PowerShell → DC pivot → LSASS
│       ├── ransomware_outbreak.json  # VSS purge → log clear → mass encryption
│       └── mixed_enterprise.json     # Stealth attack embedded in clean traffic
├── tests/
│   ├── test_pipeline.py              # Log ingestion & normalization unit tests
│   ├── test_engine.py                # Graph, anomaly, and risk engine unit tests
│   ├── test_evaluation.py            # Benchmark & zero-false-alarm assertions
│   └── test_evidence_reasoning.py    # 5 evidence cases: LIKELY_ATTACK, NORMAL,
│                                     # INSUFFICIENT_EVIDENCE, mixed noise, traceability
├── .gitignore
├── requirements.txt
├── README.md
└── run.py                            # One-click launcher (server + optional eval)
```

---

## 15. Test Coverage

```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.0.2

tests/test_engine.py::test_provenance_graph_building          PASSED
tests/test_engine.py::test_anomaly_detector_scoring           PASSED
tests/test_engine.py::test_risk_engine_calculation            PASSED
tests/test_evaluation.py::test_benign_baseline_zero_false_positives  PASSED
tests/test_evaluation.py::test_insider_usb_exfiltration_prompt_scenario  PASSED
tests/test_evaluation.py::test_benchmark_suite_metrics        PASSED
tests/test_evidence_reasoning.py::test_1_strong_attack_yields_likely_attack  PASSED
tests/test_evidence_reasoning.py::test_2_legitimate_activity_yields_normal  PASSED
tests/test_evidence_reasoning.py::test_3_suspicious_incomplete_yields_insufficient_evidence  PASSED
tests/test_evidence_reasoning.py::test_4_mixed_noise_still_detects_attack  PASSED
tests/test_evidence_reasoning.py::test_5_every_evidence_reference_maps_to_real_source_event  PASSED
tests/test_pipeline.py::test_windows_event_log_normalization  PASSED
tests/test_pipeline.py::test_usb_peripheral_normalization      PASSED

============================= 13 passed in 0.41s =============================
```

---

## 16. License

This project is released under the **MIT License**.

---

> *"Give every alert the evidence it deserves — or don't raise it at all."*
> — AegisGraph-CTI Design Philosophy
