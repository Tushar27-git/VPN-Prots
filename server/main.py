"""
FastAPI Server & REST API for IPsec Protocol Analyzer & Security Assessment Framework.
Provides modular REST endpoints for PCAP upload, benchmark sample analysis,
and Executive/Technical report rendering.
Fully offline — zero external cloud API connections.
"""

import os
import sys
import json
import shutil
import tempfile

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from typing import Dict, List, Any, Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from engine.protocol.ike_parser import DeterministicIKEParser
from engine.protocol.fingerprinter import ImplementationFingerprinter
from engine.ml.feature_extractor import ESPFlowFeatureExtractor
from engine.ml.classifier import ESPTrafficClassifier
from engine.security.scorer import IPsecSecurityScorer
from engine.reporting.report_generator import UnifiedReportGenerator

# Initialize FastAPI App
app = FastAPI(
    title="Antigravity IPsec VPN Protocol Analyzer & Security Framework",
    description="Offline Defensive Security Research & Forensic Audit Platform (PS ID 26160)",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Engine Components
ike_parser = DeterministicIKEParser()
fingerprinter = ImplementationFingerprinter()
feature_extractor = ESPFlowFeatureExtractor()
classifier = ESPTrafficClassifier()
scorer = IPsecSecurityScorer()
report_generator = UnifiedReportGenerator()

# In-memory audit cache
AUDIT_CACHE: Dict[str, Dict[str, Any]] = {}


def run_full_pipeline(pcap_path: str, filename: str) -> Dict[str, Any]:
    """Executes the complete deterministic + ML + scoring pipeline."""
    # 1. Deterministic Protocol Parsing (Zero ML)
    parsed_data = ike_parser.parse_pcap_file(pcap_path)

    # 2. Deterministic Implementation Fingerprinting (ike-scan + TOS heuristic)
    fingerprint_data = fingerprinter.fingerprint_session(parsed_data)

    # 3. ESP Flow Feature Extraction (Leroux et al. 2018 methodology)
    esp_packets = parsed_data.get("esp_packets", [])
    features_data = feature_extractor.extract_features_from_packets(esp_packets)

    # 4. Calibrated ML Traffic Classification (Flow features only)
    if features_data.get("vector"):
        classification_data = classifier.predict_flow(
            feature_vector=features_data["vector"],
            packet_count=features_data["packet_count"]
        )
    else:
        classification_data = {
            "predicted_class": "No Encrypted ESP Traffic Observed",
            "calibrated_confidence": 0.0,
            "is_confident": False,
            "probabilities": {cat: 0.0 for cat in classifier.CATEGORIES},
            "status": "NO_ESP_TRAFFIC",
            "message": "Capture contains only handshake / non-ESP packets."
        }

    # 5. NIST SP 800-77 & RFC Security Scoring
    security_data = scorer.score_assessment(parsed_data, fingerprint_data)

    # 6. Assemble Canonical Unified Model
    canonical_model = report_generator.assemble_canonical_data_model(
        filename=filename,
        parsed_data=parsed_data,
        fingerprint_data=fingerprint_data,
        features_data=features_data,
        classification_data=classification_data,
        security_data=security_data,
    )

    # Cache report
    AUDIT_CACHE[canonical_model["report_id"]] = canonical_model
    return canonical_model


@app.get("/api/health")
async def health_check():
    return {
        "status": "ONLINE_AIR_GAPPED",
        "engine_version": "2.0.0-research-hardened",
        "offline_guarantee": True,
        "external_network_calls": 0,
        "standards": ["NIST SP 800-77 Rev. 1 (June 2020)", "RFC 8221", "RFC 8247", "RFC 9370 (PQC)"],
    }


@app.post("/api/analyze/pcap")
async def analyze_uploaded_pcap(file: UploadFile = File(...)):
    """Upload and analyze any PCAP / PCAPNG packet trace."""
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Invalid file type. Supported formats: .pcap, .pcapng, .cap")

    # Save to temp file
    temp_dir = tempfile.mkdtemp()
    temp_file_path = os.path.join(temp_dir, file.filename)
    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        result = run_full_pipeline(temp_file_path, file.filename)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline error analyzing PCAP: {str(e)}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/api/dataset/samples")
async def list_sample_benchmarks():
    """Returns the library of pre-generated benchmark matrix PCAPs."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples_dir = os.path.join(base_dir, "dataset", "samples")
    if not os.path.exists(samples_dir):
        samples_dir = os.path.abspath("dataset/samples")
    if not os.path.exists(samples_dir):
        return []

    samples = []
    for f in os.listdir(samples_dir):
        if f.endswith(".json"):
            json_path = os.path.join(samples_dir, f)
            try:
                with open(json_path, "r", encoding="utf-8") as meta_f:
                    meta = json.load(meta_f)
                    pcap_name = meta.get("filename") or f.replace(".json", ".pcap")
                    samples.append({
                        "id": pcap_name.replace(".pcap", ""),
                        "filename": pcap_name,
                        "title": meta.get("suite_name", pcap_name),
                        "traffic_type": meta.get("traffic_type", "Unknown"),
                        "security_tier": meta.get("security_tier", "NIST_APPROVED"),
                        "nist_status": meta.get("nist_status", "Approved"),
                        "dh_group": meta.get("dh_group", "ECP-384"),
                        "is_pqc": meta.get("is_pqc", False),
                    })
            except Exception:
                continue

    return sorted(samples, key=lambda x: x["filename"])


@app.get("/api/dataset/load-sample/{sample_filename}")
async def load_sample_benchmark(sample_filename: str):
    """Executes the analysis pipeline on a built-in benchmark PCAP."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample_path = os.path.join(base_dir, "dataset", "samples", sample_filename)
    if not os.path.exists(sample_path):
        sample_path = os.path.abspath(os.path.join("dataset", "samples", sample_filename))
    if not os.path.exists(sample_path):
        raise HTTPException(status_code=404, detail=f"Sample PCAP '{sample_filename}' not found in dataset library.")

    result = run_full_pipeline(sample_path, sample_filename)
    return result


@app.get("/api/reports/executive/{report_id}")
async def get_executive_report_html(report_id: str):
    if report_id not in AUDIT_CACHE:
        raise HTTPException(status_code=404, detail=f"Audit report '{report_id}' not found in session cache.")
    html = report_generator.render_executive_report(AUDIT_CACHE[report_id])
    return HTMLResponse(content=html)


@app.get("/api/reports/technical/{report_id}")
async def get_technical_report_html(report_id: str):
    if report_id not in AUDIT_CACHE:
        raise HTTPException(status_code=404, detail=f"Audit report '{report_id}' not found in session cache.")
    html = report_generator.render_technical_report(AUDIT_CACHE[report_id])
    return HTMLResponse(content=html)


# Mount UI static files
ui_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui")
if os.path.exists(ui_dir):
    app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host="127.0.0.1", port=8000, reload=False)
