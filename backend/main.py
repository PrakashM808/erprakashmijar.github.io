"""
main.py — PM::OFFSEC Security Dashboard API
FastAPI backend with live scanning, remote SSH scanning, network discovery
"""
import os
import json
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import anthropic

load_dotenv()

from scanner import local_scan, remote_scan, discover_network_devices

app = FastAPI(
    title="PM::OFFSEC Security Scanner API",
    description="Live security scanning API for erprakashmijar.com dashboard",
    version="2.0.0"
)

# ── CORS — allow your domain + localhost ─────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://erprakashmijar.com",
        "https://www.erprakashmijar.com",
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "null",  # allow file:// during dev
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── IN-MEMORY SCAN HISTORY ───────────────────────────────────────
scan_history: dict[str, list] = {}  # keyed by device IP

# ── REQUEST MODELS ───────────────────────────────────────────────
class RemoteScanRequest(BaseModel):
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    key_path: Optional[str] = None

class AIRequest(BaseModel):
    scan_data: dict
    question: Optional[str] = None

class NetworkDiscoverRequest(BaseModel):
    subnet: Optional[str] = None

# ── HEALTH CHECK ────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "status": "online",
        "service": "PM::OFFSEC Security Scanner API",
        "version": "2.0.0",
        "endpoints": ["/api/scan/local", "/api/scan/remote", "/api/scan/network", "/api/ai/analyze", "/api/ai/chat", "/api/history/{ip}"]
    }

@app.get("/api/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}

# ── LOCAL SCAN ───────────────────────────────────────────────────
@app.get("/api/scan/local")
def scan_local():
    """Scan the machine running this API server"""
    try:
        result = local_scan()
        # Save to history
        ip = result.get('ip', '127.0.0.1')
        if ip not in scan_history:
            scan_history[ip] = []
        scan_history[ip].append({
            "date": datetime.now().strftime("%b %d"),
            "score": result['security_score'],
            "timestamp": result['timestamp']
        })
        if len(scan_history[ip]) > 10:
            scan_history[ip] = scan_history[ip][-10:]
        result['score_history'] = scan_history[ip][-5:]
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# ── REMOTE SCAN ──────────────────────────────────────────────────
@app.post("/api/scan/remote")
def scan_remote(req: RemoteScanRequest):
    """Scan a remote Linux machine via SSH"""
    try:
        result = remote_scan(
            host=req.host,
            port=req.port,
            username=req.username,
            password=req.password,
            key_path=req.key_path
        )
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        # Save history
        ip = result.get('ip', req.host)
        if ip not in scan_history:
            scan_history[ip] = []
        scan_history[ip].append({
            "date": datetime.now().strftime("%b %d"),
            "score": result['security_score'],
            "timestamp": result['timestamp']
        })
        if len(scan_history[ip]) > 10:
            scan_history[ip] = scan_history[ip][-10:]
        result['score_history'] = scan_history[ip][-5:]
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── NETWORK DISCOVERY ────────────────────────────────────────────
@app.post("/api/scan/network")
def scan_network(req: NetworkDiscoverRequest):
    """Discover all live devices on the local network"""
    try:
        devices = discover_network_devices(req.subnet)
        return {
            "subnet": req.subnet or "auto-detected",
            "devices_found": len(devices),
            "devices": devices,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── SCAN HISTORY ─────────────────────────────────────────────────
@app.get("/api/history/{ip}")
def get_history(ip: str):
    """Get scan history for a device"""
    ip_clean = ip.replace("-", ".")
    return {
        "ip": ip_clean,
        "scans": scan_history.get(ip_clean, [])
    }

@app.get("/api/history")
def get_all_history():
    """Get all scan history"""
    return {"history": scan_history}

# ── AI ANALYSIS ──────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert cybersecurity analyst embedded in a live Security Audit Dashboard.
Your role is to analyze real Linux system security scan results and provide:
1. Clear, actionable explanations (explain all jargon)
2. Prioritized remediation steps with exact bash commands in code blocks
3. Business risk context
4. CVSS-aligned severity context

Be concise but thorough. Professional but accessible tone.
Format with clear sections using headers."""

@app.post("/api/ai/analyze")
async def ai_analyze(req: AIRequest):
    """Full AI security analysis of scan results"""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured in .env")
    try:
        client = anthropic.Anthropic(api_key=api_key)
        prompt = f"""Analyze this LIVE security scan and provide:
1. Executive Summary (2-3 sentences, non-technical)
2. Top 3 Critical Risks with exact business impact
3. Immediate Actions — exact bash commands for each fix
4. 30-Day Remediation Roadmap

Live scan data: {json.dumps(req.scan_data, indent=2)}"""
        message = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )
        return {"analysis": message.content[0].text, "model": "claude-opus-4-5", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ai/chat")
async def ai_chat(req: AIRequest):
    """Chat with AI about scan results"""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")
    if not req.question:
        raise HTTPException(status_code=400, detail="Question is required")
    try:
        client = anthropic.Anthropic(api_key=api_key)
        context = f"Live scan context: {json.dumps(req.scan_data, indent=2)}\n\nUser question: {req.question}" if req.scan_data else req.question
        message = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": context}]
        )
        return {"reply": message.content[0].text, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
