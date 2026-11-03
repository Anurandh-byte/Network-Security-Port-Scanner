import os
import sys
import json
import asyncio
import webbrowser
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from scanner_engine import (
    PORT_DATABASE,
    PRESETS,
    resolve_target,
    scan_single_port,
    PortScannerEngine
)

app = FastAPI(
    title="CyberPort Scanner Pro API",
    description="High-performance network port scanning & telemetry engine",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active scans map to allow cancellation
active_engines: Dict[str, PortScannerEngine] = {}

class TargetInfoRequest(BaseModel):
    target: str

class ScanRequest(BaseModel):
    target: str
    preset: Optional[str] = "standard"
    custom_ports: Optional[str] = None
    threads: Optional[int] = 60
    timeout: Optional[float] = 0.25

def parse_ports(preset: Optional[str], custom_ports: Optional[str]) -> List[int]:
    """Parses port selection from preset or custom input."""
    if custom_ports and custom_ports.strip():
        ports = set()
        parts = custom_ports.replace(" ", "").split(",")
        for p in parts:
            if not p:
                continue
            if "-" in p:
                sub_parts = p.split("-")
                if len(sub_parts) == 2 and sub_parts[0].isdigit() and sub_parts[1].isdigit():
                    start_p = max(1, min(int(sub_parts[0]), 65535))
                    end_p = max(1, min(int(sub_parts[1]), 65535))
                    if start_p > end_p:
                        start_p, end_p = end_p, start_p
                    # Limit range span to prevent memory issues
                    for port_num in range(start_p, min(end_p + 1, start_p + 20000)):
                        ports.add(port_num)
            elif p.isdigit():
                val = int(p)
                if 1 <= val <= 65535:
                    ports.add(val)
        if ports:
            return sorted(list(ports))

    if preset and preset in PRESETS:
        return PRESETS[preset]["ports"]

    return PRESETS["standard"]["ports"]


@app.get("/api/presets")
def get_presets():
    return {
        key: {
            "name": val["name"],
            "description": val["description"],
            "port_count": len(val["ports"]),
            "sample_ports": val["ports"][:10]
        }
        for key, val in PRESETS.items()
    }


@app.post("/api/target-info")
def get_target_info(req: TargetInfoRequest):
    try:
        info = resolve_target(req.target)
        return {"status": "ok", "data": info}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/scan")
def run_scan_sync(req: ScanRequest):
    try:
        ports = parse_ports(req.preset, req.custom_ports)
        engine = PortScannerEngine(
            target=req.target,
            ports=ports,
            max_workers=req.threads or 50,
            timeout=req.timeout or 0.25
        )
        summary = engine.run()
        return {"status": "ok", "summary": summary}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.websocket("/ws/scan")
async def websocket_scan_endpoint(websocket: WebSocket):
    await websocket.accept()
    session_id = str(id(websocket))
    current_engine: Optional[PortScannerEngine] = None

    try:
        while True:
            raw_data = await websocket.receive_text()
            data = json.loads(raw_data)
            action = data.get("action")

            if action == "stop":
                if current_engine:
                    current_engine.cancel()
                    await websocket.send_json({"type": "scan_stopped"})
                continue

            if action == "start":
                if current_engine:
                    current_engine.cancel()

                target = data.get("target", "").strip()
                if not target:
                    await websocket.send_json({"type": "error", "message": "Target address cannot be empty."})
                    continue

                preset = data.get("preset", "standard")
                custom_ports = data.get("custom_ports")
                threads = int(data.get("threads", 60))
                timeout = float(data.get("timeout", 0.25))

                try:
                    ports = parse_ports(preset, custom_ports)
                except Exception as e:
                    await websocket.send_json({"type": "error", "message": f"Port parsing error: {e}"})
                    continue

                loop = asyncio.get_event_loop()
                queue: asyncio.Queue = asyncio.Queue()

                def progress_cb(event: Dict[str, Any]):
                    loop.call_soon_threadsafe(queue.put_nowait, event)

                try:
                    engine = PortScannerEngine(
                        target=target,
                        ports=ports,
                        max_workers=threads,
                        timeout=timeout
                    )
                    current_engine = engine
                    active_engines[session_id] = engine

                    # Start engine in background thread pool
                    scan_future = loop.run_in_executor(None, engine.run, progress_cb)

                    # Stream queue events to WebSocket in real-time
                    while not scan_future.done() or not queue.empty():
                        try:
                            # Drain batch of events to keep UI ultra responsive without lagging
                            events = []
                            # Wait for at least one event
                            first_event = await asyncio.wait_for(queue.get(), timeout=0.08)
                            events.append(first_event)
                            
                            # Gather any other queued events up to 50
                            while not queue.empty() and len(events) < 50:
                                events.append(queue.get_nowait())

                            if events:
                                await websocket.send_json({"type": "batch_update", "events": events})
                        except asyncio.TimeoutError:
                            # Periodic heartbeat check
                            if scan_future.done() and queue.empty():
                                break

                    # Ensure final scan result is captured
                    await scan_future

                except Exception as e:
                    await websocket.send_json({"type": "error", "message": str(e)})
                finally:
                    if session_id in active_engines:
                        del active_engines[session_id]

    except WebSocketDisconnect:
        if current_engine:
            current_engine.cancel()
        if session_id in active_engines:
            del active_engines[session_id]
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


# Ensure static directory exists and serve files
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def serve_index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>CyberPort Scanner Pro</h1><p>Building frontend assets...</p>")


def open_browser_delayed(url: str, delay: float = 1.2):
    """Opens browser after server start."""
    def _open():
        time.sleep(delay)
        webbrowser.open(url)
    import threading
    import time
    threading.Thread(target=_open, daemon=True).start()


if __name__ == "__main__":
    port = 8000
    host = "127.0.0.1"
    url = f"http://{host}:{port}"
    print("\n" + "=" * 60)
    print("      🚀 CYBERPORT SCANNER PRO - WEB APPLICATION")
    print("=" * 60)
    print(f"[*] Starting local server at: {url}")
    print("[*] Opening browser automatically...")
    print("=" * 60 + "\n")
    
    open_browser_delayed(url)
    uvicorn.run("app:app", host=host, port=port, reload=False)
