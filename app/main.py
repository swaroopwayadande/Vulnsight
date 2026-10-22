"""Local VulnSight web application and API."""

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

APP_DIR = Path(__file__).resolve().parent
app = FastAPI(
    title="VulnSight",
    description="Local, low-impact web security assessment for authorized targets",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=APP_DIR / "templates")


class ScanRequest(BaseModel):
    """Validated request for one authorized target assessment."""

    url: str = Field(min_length=1, max_length=2048)
    authorized: bool
    local_lab: bool = False
    path_checks: bool = True


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    """Render the dashboard and latest scan history."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"history": list_scans()},
    )


@app.get("/health")
def health() -> dict[str, str]:
    """Return a local process health response."""
    return {"status": "ok"}


@app.get("/api/scans")
def history() -> list[dict]:
    """Return recent scans in local history."""
    return list_scans()


@app.post("/api/scans")
def create_scan(payload: ScanRequest) -> dict:
    """Validate authorization, run one bounded scan, and persist its result."""
    if not payload.authorized:
        raise HTTPException(
            status_code=400,
            detail="Confirm that you own or are authorized to assess this target.",
        )
    try:
        result = run_scan(
            payload.url,
            local_lab=payload.local_lab,
            path_checks=payload.path_checks,
        )
    except TargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    save_scan(result)
    return result


@app.get("/api/scans/{scan_id}")
def scan_details(scan_id: str) -> dict:
    """Return one scan result or a 404 response."""
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return result


@app.get("/api/scans/{scan_id}/report.json")
def report_json(scan_id: str) -> JSONResponse:
    """Download one scan result as JSON."""
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    headers = {"Content-Disposition": f'attachment; filename="vulnsight-{scan_id}.json"'}
    return JSONResponse(result, headers=headers)


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: str, request: Request) -> HTMLResponse:
    """Render one escaped, printable HTML report."""
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={"report": result},
    )
