import os
import json
import asyncio
import uuid
import signal

import sys
from datetime import datetime
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from db import supabase

load_dotenv()

app = FastAPI(title="Sentinel API", version="2.0.0")

# CORS
origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

class ScanState:
    """Tracks one running scan."""
    def __init__(self, scan_id: str, target_url: str):
        self.scan_id = scan_id
        self.target_url = target_url
        self.processes: Dict[int, subprocess.Popen] = {}
        self.websockets: Set[WebSocket] = set()
        self.events: List[dict] = []
        self.findings: List[dict] = []
        self.status: str = "running"
        self.agents_complete: int = 0
        self.total_agents: int = 5

active_scans: Dict[str, ScanState] = {}

AGENT_ROLES = [
    {"id": 1, "role": "sqli",  "name": "SQL Injection"},
    {"id": 2, "role": "xss",   "name": "XSS"},
    {"id": 3, "role": "auth",  "name": "Auth Bypass"},
    {"id": 4, "role": "idor",  "name": "IDOR"},
    {"id": 5, "role": "csrf",  "name": "CSRF"},
]

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target_url: str
    agents: Optional[List[str]] = None  # unused for now, always 5

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    agents_spawned: int

# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {"message": "Sentinel API", "version": "2.0.0"}

@app.get("/health")
def health():
    return {"status": "healthy", "service": "sentinel-api"}

@app.post("/api/scans/start", response_model=ScanResponse, status_code=201)
async def start_scan(req: ScanRequest):
    if not req.target_url:
        raise HTTPException(400, "target_url is required")

    scan_id = str(uuid.uuid4())

    # Persist to Supabase
    try:
        supabase.table("security_runs").insert({
            "id": scan_id,
            "target_url": req.target_url,
            "status": "RUNNING",
            "started_at": datetime.utcnow().isoformat(),
        }).execute()

        sessions = []
        for agent in AGENT_ROLES:
            sessions.append({
                "run_id": scan_id,
                "agent_type": agent["role"],
                "status": "QUEUED",
            })
        supabase.table("agent_sessions").insert(sessions).execute()
    except Exception as e:
        print(f"Supabase insert error (non-fatal): {e}")

    # Create scan state
    state = ScanState(scan_id, req.target_url)
    active_scans[scan_id] = state

    # Spawn agents
    asyncio.create_task(_spawn_agents(state))

    return ScanResponse(scan_id=scan_id, status="running", agents_spawned=5)


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    state = active_scans.get(scan_id)
    if not state:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id": scan_id,
        "status": state.status,
        "target_url": state.target_url,
        "findings": state.findings,
        "agents_complete": state.agents_complete,
        "total_agents": state.total_agents,
    }


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    state = active_scans.get(scan_id)
    if not state:
        raise HTTPException(404, "Scan not found")

    for pid, proc in state.processes.items():
        try:
            proc.kill()
        except Exception:
            pass

    state.status = "stopped"
    await _broadcast(state, {"type": "scan.stopped", "scanId": scan_id})

    try:
        supabase.table("security_runs").update(
            {"status": "CANCELLED", "ended_at": datetime.utcnow().isoformat()}
        ).eq("id", scan_id).execute()
    except Exception:
        pass

    return {"status": "stopped"}

# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    state = active_scans.get(scan_id)
    if not state:
        await websocket.send_json({"type": "error", "message": "Scan not found"})
        await websocket.close()
        return

    state.websockets.add(websocket)

    # Send existing events as catch-up
    for event in state.events:
        try:
            await websocket.send_json(event)
        except Exception:
            break

    try:
        while True:
            # Keep connection alive, ignore client messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        state.websockets.discard(websocket)


# ---------------------------------------------------------------------------
# Agent orchestration
# ---------------------------------------------------------------------------

async def _spawn_agents(state: ScanState):
    """Spawn 5 agent subprocesses and stream their stdout JSON lines in real-time."""
    agent_script = os.path.join(os.path.dirname(__file__), "agents", "agent_harness.py")

    tasks = []
    for agent in AGENT_ROLES:
        env = {
            **os.environ,
            "AGENT_ID": str(agent["id"]),
            "AGENT_ROLE": agent["role"],
            "TARGET_URL": state.target_url,
            "SCAN_ID": state.scan_id,
            "PYTHONUNBUFFERED": "1",
        }

        proc = await asyncio.create_subprocess_exec(
            sys.executable, agent_script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            limit=10 * 1024 * 1024,  # 10 MB — screenshots are large base64 lines
        )
        state.processes[agent["id"]] = proc
        tasks.append(asyncio.create_task(_read_agent_output(state, agent, proc)))

    # Wait for all agents
    await asyncio.gather(*tasks, return_exceptions=True)

    # Mark scan complete
    state.status = "completed"
    completion_event = {
        "type": "scan.complete",
        "scanId": state.scan_id,
        "data": {"totalFindings": len(state.findings)},
        "timestamp": datetime.utcnow().isoformat(),
    }
    state.events.append(completion_event)
    await _broadcast(state, completion_event)

    try:
        supabase.table("security_runs").update(
            {"status": "COMPLETED", "ended_at": datetime.utcnow().isoformat()}
        ).eq("id", state.scan_id).execute()
    except Exception:
        pass


async def _read_agent_output(state: ScanState, agent: dict, proc):
    """Read JSON lines from an agent subprocess stdout — one line at a time, streamed live."""
    try:
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break  # EOF — process finished
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {
                    "type": "agent.log",
                    "agentId": agent["id"],
                    "role": agent["role"],
                    "data": {"message": line},
                }

            # Enrich
            event.setdefault("agentId", agent["id"])
            event.setdefault("role", agent["role"])
            event.setdefault("scanId", state.scan_id)
            event.setdefault("timestamp", datetime.utcnow().isoformat())

            state.events.append(event)

            # Track findings
            if event.get("type") == "vulnerability.found":
                vuln = event.get("data", {}).get("vulnerability", event.get("data", {}))
                state.findings.append(vuln)
                try:
                    supabase.table("findings").insert({
                        "run_id": state.scan_id,
                        "agent_type": agent["role"],
                        "severity": vuln.get("severity", "MEDIUM"),
                        "title": vuln.get("type", "Unknown"),
                        "evidence": vuln.get("evidence", ""),
                        "recommendation": vuln.get("recommendation", ""),
                    }).execute()
                except Exception:
                    pass

            if event.get("type") == "agent.complete":
                state.agents_complete += 1
                try:
                    supabase.table("agent_sessions").update(
                        {"status": "COMPLETED", "progress": 100}
                    ).eq("run_id", state.scan_id).eq("agent_type", agent["role"]).execute()
                except Exception:
                    pass

            # Broadcast to all connected WebSocket clients IMMEDIATELY
            await _broadcast(state, event)

    except Exception as e:
        print(f"[Agent {agent['id']}] Stream reader error: {e}")

    # Wait for process to finish and read stderr
    await proc.wait()
    try:
        stderr_data = await proc.stderr.read()
        stderr_text = stderr_data.decode("utf-8", errors="replace").strip()
        if stderr_text:
            print(f"[Agent {agent['id']} stderr] {stderr_text[:500]}")
    except Exception:
        pass


async def _broadcast(state: ScanState, event: dict):
    """Send event to all connected WebSocket clients."""
    dead = set()
    for ws in state.websockets:
        try:
            await ws.send_json(event)
        except Exception:
            dead.add(ws)
    state.websockets -= dead


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
