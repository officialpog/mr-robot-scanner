"""
Mr. Robot Scanner - Scan API
Handles scan requests and result retrieval.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
import time
import threading

from database.database import get_db, SessionLocal
from database.models import Scan, User
from models.schemas import ScanRequest, ScanResponse, DashboardStats
from api.auth import get_current_user
from scanners.nmap_scanner import run_nmap_scan
from scanners.whatweb_scanner import run_whatweb_scan
from scanners.ssl_checker import check_ssl_tls
from scanners.nuclei_scanner import run_nuclei_scan
from scanners.subfinder_scanner import run_subfinder_scan
from scanners.headers_checker import check_security_headers

router = APIRouter()


def calculate_risk_score(vulnerabilities: list) -> int:
    """Calculate risk score 0-100"""
    score = 0
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 2}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low").lower()
        score += weights.get(severity, 1)
    return min(score, 100)


def run_full_scan_sync(scan_id: int, target: str):
    """Execute full scan in background thread"""
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        start_time = time.time()
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        # Step 1: Port Scan
        scan.progress = 10
        scan.current_step = "Port scanning"
        db.commit()
        ports_result = run_nmap_scan(target)
        scan.ports_data = ports_result
        scan.ports_count = len(ports_result)
        scan.progress = 25
        db.commit()

        # Step 2: Technology Detection
        scan.progress = 30
        scan.current_step = "Detecting technologies"
        db.commit()
        tech_result = run_whatweb_scan(target)
        scan.technologies_data = tech_result
        scan.progress = 45
        db.commit()

        # Step 3: SSL/TLS
        scan.progress = 50
        scan.current_step = "Checking SSL/TLS"
        db.commit()
        ssl_result = check_ssl_tls(target)
        scan.ssl_data = ssl_result
        scan.progress = 60
        db.commit()

        # Step 4: Security Headers
        scan.progress = 65
        scan.current_step = "Checking headers"
        db.commit()
        headers_result = check_security_headers(target)
        scan.headers_data = headers_result
        scan.progress = 75
        db.commit()

        # Step 5: Vulnerability Scan
        scan.progress = 80
        scan.current_step = "Scanning vulnerabilities"
        db.commit()
        vulns_result = run_nuclei_scan(target)
        scan.vulnerabilities_data = vulns_result
        scan.vulns_count = len(vulns_result)
        scan.progress = 90
        db.commit()

        # Step 6: Subdomains
        scan.progress = 92
        scan.current_step = "Enumerating subdomains"
        db.commit()
        subdomains_result = run_subfinder_scan(target)
        scan.subdomains_data = subdomains_result
        scan.subdomains_count = len(subdomains_result)
        scan.progress = 95
        db.commit()

        # Calculate risk
        scan.risk_score = calculate_risk_score(vulns_result)
        scan.progress = 100
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.duration_seconds = round(time.time() - start_time, 2)
        db.commit()

    except Exception as e:
        scan.status = "failed"
        scan.error_message = str(e)
        db.commit()
    finally:
        db.close()


@router.post("/scan/public")
async def start_public_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """Start a scan without authentication"""
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    scan = Scan(
        target=target,
        scan_type=request.scan_type,
        status="pending",
        progress=0
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    thread = threading.Thread(
        target=run_full_scan_sync,
        args=(scan.id, target),
        daemon=True
    )
    thread.start()

    return {
        "scan_id": scan.id,
        "target": target,
        "status": "scan_started",
        "message": f"Scan initiated for {target}"
    }


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan results by ID"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse(
        id=scan.id,
        target=scan.target,
        status=scan.status,
        progress=scan.progress,
        risk_score=scan.risk_score,
        risk_level="critical" if scan.risk_score >= 75 else "high" if scan.risk_score >= 50 else "medium" if scan.risk_score >= 25 else "low",
        ports=scan.ports_data or [],
        technologies=scan.technologies_data or [],
        vulnerabilities=scan.vulnerabilities_data or [],
        subdomains=scan.subdomains_data or [],
        ssl_info=scan.ssl_data or {},
        headers_info=scan.headers_data or {},
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=scan.duration_seconds,
        error_message=scan.error_message,
        created_at=scan.created_at
    )


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    scans = db.query(Scan).all()
    total = len(scans)
    
    all_vulns = []
    for s in scans:
        if s.vulnerabilities_data:
            all_vulns.extend(s.vulnerabilities_data)
    
    return DashboardStats(
        total_scans=total,
        completed_scans=sum(1 for s in scans if s.status == "completed"),
        failed_scans=sum(1 for s in scans if s.status == "failed"),
        running_scans=sum(1 for s in scans if s.status == "running"),
        total_vulnerabilities=len(all_vulns),
        critical_count=sum(1 for v in all_vulns if v.get("severity") == "critical"),
        high_count=sum(1 for v in all_vulns if v.get("severity") == "high"),
        medium_count=sum(1 for v in all_vulns if v.get("severity") == "medium"),
        low_count=sum(1 for v in all_vulns if v.get("severity") == "low"),
        average_risk_score=sum(s.risk_score or 0 for s in scans) / total if total > 0 else 0
    )