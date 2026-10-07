"""
FastAPI Application for AegisGraph-CTI
Provides REST endpoints for threat analysis, graph visualization,
evidence proof extraction, and benchmark evaluations.
Serves the modern frontend Cyber Command Center.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.models import IncidentReport
from backend.evaluation.evaluator import BenchmarkEvaluator

app = FastAPI(
    title="AegisGraph-CTI Engine",
    description="AI-Powered Cyber Threat Intelligence & Multi-Stage Attack Provenance System",
    version="1.0.0"
)

# Enable CORS for local development and web dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATASETS_DIR = Path(__file__).resolve().parent.parent / "data" / "datasets"
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

evaluator = BenchmarkEvaluator()


class CustomLogPayload(BaseModel):
    logs: List[Dict[str, Any]]


@app.get("/api/health")
def health_check():
    return {
        "status": "operational",
        "system": "AegisGraph-CTI",
        "engine_version": "1.0.0",
        "features": [
            "Heterogeneous Provenance Graph",
            "Multi-Stage Attack Chain Reconstruction",
            "Verifiable Forensic Evidence Citations",
            "Zero False Positive Suppression Gate",
            "Automated SOC Mitigation Playbooks"
        ]
    }


@app.get("/api/datasets")
def list_datasets():
    """Returns available pre-configured benchmark datasets with metadata."""
    return [
        {
            "id": "benign_baseline",
            "title": "Clean Enterprise Baseline (Zero False Alarm Test)",
            "description": "Standard business operations, routine admin checks, Zoom/Chrome traffic. Tests system precision and quietness.",
            "expected_verdict": "BENIGN_BASELINE",
            "file": "benign_baseline.json"
        },
        {
            "id": "insider_usb_exfil",
            "title": "Prompt Scenario: Insider Threat & USB Exfiltration",
            "description": "Unusual off-hours remote login -> novel confidential financial asset traversal -> removable USB mount & data theft.",
            "expected_verdict": "MALICIOUS_ATTACK_CHAIN",
            "file": "insider_usb_exfil.json"
        },
        {
            "id": "apt_lateral_movement",
            "title": "Advanced Persistent Threat (APT): Lateral Movement & C2",
            "description": "Tor exit login -> PowerShell download cradle -> lateral SMB pivot to DC-CORP-01 -> LSASS dump -> C2 exfiltration.",
            "expected_verdict": "MALICIOUS_ATTACK_CHAIN",
            "file": "apt_lateral_movement.json"
        },
        {
            "id": "ransomware_outbreak",
            "title": "Ransomware Attack Chain: Defense Evasion & Encryption",
            "description": "Macro download -> Volume Shadow Copy purge -> Windows Security Event Log clearance -> mass encryption burst.",
            "expected_verdict": "MALICIOUS_ATTACK_CHAIN",
            "file": "ransomware_outbreak.json"
        },
        {
            "id": "mixed_enterprise",
            "title": "Mixed Enterprise Traffic: Attack in the Haystack",
            "description": "Clean enterprise background noise with interleaved multi-stage insider exfiltration attack.",
            "expected_verdict": "MALICIOUS_ATTACK_CHAIN",
            "file": "mixed_enterprise.json"
        }
    ]


@app.post("/api/analyze/preset/{dataset_id}", response_model=IncidentReport)
def analyze_preset(dataset_id: str):
    """Analyzes a pre-configured benchmark dataset."""
    target_path = DATASETS_DIR / f"{dataset_id}.json"
    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_id}' not found.")

    with open(target_path, "r", encoding="utf-8") as f:
        raw_events = json.load(f)

    # If analyzing an attack dataset, optionally use benign_baseline as baseline profile
    baseline_path = DATASETS_DIR / "benign_baseline.json"
    baseline_events = None
    if baseline_path.exists() and dataset_id != "benign_baseline":
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline_events = json.load(f)

    report = evaluator.analyze_dataset(raw_events, baseline_events=baseline_events)
    return report


@app.post("/api/analyze/custom", response_model=IncidentReport)
def analyze_custom(payload: CustomLogPayload):
    """Analyzes custom logs submitted via UI or API."""
    if not payload.logs:
        raise HTTPException(status_code=400, detail="Log list cannot be empty.")

    baseline_path = DATASETS_DIR / "benign_baseline.json"
    baseline_events = None
    if baseline_path.exists():
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline_events = json.load(f)

    report = evaluator.analyze_dataset(payload.logs, baseline_events=baseline_events)
    return report


@app.get("/api/benchmark")
def run_benchmark():
    """Runs all benchmark scenarios and returns comprehensive evaluation metrics."""
    scenarios = [
        {
            "name": "Benign Enterprise Baseline (Zero-FP Verification)",
            "file": "benign_baseline.json",
            "ground_truth_is_attack": False
        },
        {
            "name": "Insider Threat USB Exfiltration (Prompt Example)",
            "file": "insider_usb_exfil.json",
            "ground_truth_is_attack": True
        },
        {
            "name": "APT Lateral Movement to Domain Controller",
            "file": "apt_lateral_movement.json",
            "ground_truth_is_attack": True
        },
        {
            "name": "Ransomware Outbreak & Anti-Forensics",
            "file": "ransomware_outbreak.json",
            "ground_truth_is_attack": True
        },
        {
            "name": "Mixed Traffic (Embedded Stealth Attack)",
            "file": "mixed_enterprise.json",
            "ground_truth_is_attack": True
        }
    ]

    loaded_scenarios = []
    for sc in scenarios:
        p = DATASETS_DIR / sc["file"]
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                loaded_scenarios.append({
                    "name": sc["name"],
                    "events": json.load(f),
                    "ground_truth_is_attack": sc["ground_truth_is_attack"]
                })

    benchmark_output = evaluator.run_benchmark_suite(loaded_scenarios)
    return benchmark_output


# Mount frontend static files if directory exists
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
