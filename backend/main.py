"""
ShieldAI - FastAPI Backend
Real-time threat classification, auto-block engine, and threat log API.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import time
import uuid
from datetime import datetime
from collections import defaultdict

# ── App setup ─────────────────────────────────────────────────
app = FastAPI(
    title="ShieldAI API",
    description="Real-time cloud security threat detection platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory state (use Redis/PostgreSQL in production) ───────
blocked_ips: dict[str, dict] = {}
threat_log: list[dict] = []
ip_threat_count: dict[str, int] = defaultdict(int)

BLOCK_THRESHOLD = 3   # auto-block after 3 threats from same IP
THREAT_SCORE_BLOCK = 0.85  # auto-block if single threat score > this

# ── Models ─────────────────────────────────────────────────────
class TrafficRequest(BaseModel):
    ip: str = Field(..., example="192.168.1.100")
    path: str = Field(..., example="/api/users")
    method: str = Field("GET", example="POST")
    request_rate: float = Field(..., ge=0, example=12.5)
    payload_size: float = Field(..., ge=0, example=512.0)
    unique_endpoints: int = Field(..., ge=1, example=3)
    error_rate: float = Field(..., ge=0, le=1, example=0.02)
    has_sql_keywords: int = Field(0, ge=0, le=1)
    header_anomaly: int = Field(0, ge=0, le=1)
    geo_risk_score: float = Field(0.0, ge=0, le=1)
    repeated_ip: int = Field(0, ge=0, le=1)

class BlockRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Manual block"

# ── Helpers ────────────────────────────────────────────────────
def _mock_classify(req: TrafficRequest) -> dict:
    """
    Rule-based classifier (fallback when ML model not trained).
    Replace with ml.classifier.classify() after running train_model.py
    """
    threat_score = 0.0
    label = "clean"

    if req.request_rate > 300:
        threat_score += 0.7
        label = "ddos"
    if req.has_sql_keywords:
        threat_score += 0.6
        label = "sqli"
    if req.error_rate > 0.3:
        threat_score += 0.3
    if req.header_anomaly:
        threat_score += 0.2
    if req.geo_risk_score > 0.7:
        threat_score += 0.2

    threat_score = min(threat_score, 1.0)

    if label == "clean" and threat_score > 0.3:
        label = "suspicious"

    confidence = 0.85 if label != "clean" else 0.92
    return {
        "label": label,
        "confidence": confidence,
        "threat_score": round(threat_score, 4),
        "probabilities": {
            "clean": round(1 - threat_score, 4),
            label: round(threat_score, 4)
        }
    }

def _try_ml_classify(req: TrafficRequest) -> dict:
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from ml.classifier import classify
        features = {
            "request_rate":     req.request_rate,
            "payload_size":     req.payload_size,
            "unique_endpoints": req.unique_endpoints,
            "error_rate":       req.error_rate,
            "has_sql_keywords": req.has_sql_keywords,
            "header_anomaly":   req.header_anomaly,
            "geo_risk_score":   req.geo_risk_score,
            "repeated_ip":      req.repeated_ip,
        }
        return classify(features)
    except Exception:
        return _mock_classify(req)

# ── Routes ─────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def root():
    return {"status": "ShieldAI is active", "version": "1.0.0"}

@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "ok",
        "blocked_ips": len(blocked_ips),
        "threats_logged": len(threat_log),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/classify", tags=["Classification"])
def classify_traffic(req: TrafficRequest):
    """
    Classify an incoming traffic request as clean / ddos / sqli / suspicious.
    Auto-blocks IP if threat score exceeds threshold or repeat threats detected.
    """
    start = time.time()

    # Check if already blocked
    if req.ip in blocked_ips:
        return {
            "ip": req.ip,
            "status": "blocked",
            "reason": blocked_ips[req.ip]["reason"],
            "action": "REQUEST_DROPPED"
        }

    result = _try_ml_classify(req)
    latency_ms = round((time.time() - start) * 1000, 2)

    label = result["label"]
    threat_score = result["threat_score"]
    is_threat = label != "clean"

    # Log event
    event = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.utcnow().isoformat(),
        "ip": req.ip,
        "path": req.path,
        "method": req.method,
        "label": label,
        "threat_score": threat_score,
        "confidence": result["confidence"],
        "latency_ms": latency_ms,
        "action": "ALLOW"
    }

    # Auto-block logic
    auto_blocked = False
    if is_threat:
        ip_threat_count[req.ip] += 1
        reason = None

        if threat_score >= THREAT_SCORE_BLOCK:
            reason = f"High threat score: {threat_score:.2f} ({label.upper()})"
        elif ip_threat_count[req.ip] >= BLOCK_THRESHOLD:
            reason = f"Repeated threats: {ip_threat_count[req.ip]} incidents"

        if reason:
            blocked_ips[req.ip] = {
                "ip": req.ip,
                "reason": reason,
                "blocked_at": datetime.utcnow().isoformat(),
                "threat_type": label
            }
            event["action"] = "BLOCKED"
            auto_blocked = True

    threat_log.append(event)
    # Keep last 500 events in memory
    if len(threat_log) > 500:
        threat_log.pop(0)

    return {
        **result,
        "ip": req.ip,
        "path": req.path,
        "latency_ms": latency_ms,
        "action": event["action"],
        "auto_blocked": auto_blocked,
        "event_id": event["id"]
    }

@app.get("/threats", tags=["Monitoring"])
def get_threats(limit: int = 50, label: Optional[str] = None):
    """Retrieve recent threat log entries."""
    logs = threat_log[-limit:][::-1]
    if label:
        logs = [e for e in logs if e["label"] == label]
    return {"count": len(logs), "events": logs}

@app.get("/stats", tags=["Monitoring"])
def get_stats():
    """Aggregated threat statistics."""
    from collections import Counter
    labels = [e["label"] for e in threat_log]
    counts = Counter(labels)
    total = len(threat_log) or 1
    return {
        "total_requests": len(threat_log),
        "blocked_ips": len(blocked_ips),
        "label_distribution": dict(counts),
        "threat_rate": round((total - counts.get("clean", 0)) / total, 4),
        "avg_threat_score": round(
            sum(e["threat_score"] for e in threat_log) / total, 4
        ) if threat_log else 0
    }

@app.get("/blocked-ips", tags=["Block Engine"])
def get_blocked_ips():
    """List all auto-blocked IP addresses."""
    return {"count": len(blocked_ips), "ips": list(blocked_ips.values())}

@app.post("/block", tags=["Block Engine"])
def manual_block(req: BlockRequest):
    """Manually block an IP address."""
    blocked_ips[req.ip] = {
        "ip": req.ip,
        "reason": req.reason,
        "blocked_at": datetime.utcnow().isoformat(),
        "threat_type": "manual"
    }
    return {"status": "blocked", "ip": req.ip}

@app.delete("/block/{ip}", tags=["Block Engine"])
def unblock_ip(ip: str):
    """Unblock a previously blocked IP address."""
    if ip not in blocked_ips:
        raise HTTPException(status_code=404, detail="IP not found in block list")
    del blocked_ips[ip]
    if ip in ip_threat_count:
        del ip_threat_count[ip]
    return {"status": "unblocked", "ip": ip}
