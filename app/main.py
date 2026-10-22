"""Local VulnSight web application and API."""
import json
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.requests import Request
from .database import get_scan, list_scans, save_scan
from .scanner.engine import run_scan
from .scanner.target_validation import TargetError

ROOT = Path(__file__).resolve().parent
app = FastAPI(title="VulnSight", description="Local, low-impact web security assessment for authorized targets", version="0.1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")

class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool
    local_lab: bool = False
    path_checks: bool = True

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"history": list_scans()})

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/api/scans")
def history(): return list_scans()

@app.post("/api/scans")
def create_scan(payload: ScanRequest):
    if not payload.authorized:
        raise HTTPException(400, "Confirm that you own or are authorized to assess this target.")
    try:
        result = run_scan(payload.url, local_lab=payload.local_lab, path_checks=payload.path_checks)
    except TargetError as exc:
        raise HTTPException(422, str(exc)) from exc
    save_scan(result)
    return result

@app.get("/api/scans/{scan_id}")
def scan_details(scan_id: str):
    result = get_scan(scan_id)
    if result is None: raise HTTPException(404, "Scan not found.")
    return result

@app.get("/api/scans/{scan_id}/report.json")
def report_json(scan_id: str):
    result = get_scan(scan_id)
    if result is None: raise HTTPException(404, "Scan not found.")
    return JSONResponse(result, headers={"Content-Disposition": f'attachment; filename="vulnsight-{scan_id}.json"'})

@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: str, request: Request):
    result = get_scan(scan_id)
    if result is None: raise HTTPException(404, "Scan not found.")
    return templates.TemplateResponse(request=request, name="report.html", context={"report": result})
