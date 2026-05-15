"""
Mr. Robot Scanner - Scan API
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address
import time, threading, re

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
limiter = Limiter(key_func=get_remote_address)

BLOCKED_TARGETS = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '192.168.', '10.', '172.16.']


def validate_target(target: str) -> str:
    target = re.sub(r'^https?://', '', target.strip()).rstrip('/').split(':')[0]
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    if not re.match(ip_pattern, target) and not re.match(domain_pattern, target):
        raise HTTPException(status_code=400, detail="Invalid target")
    for blocked in BLOCKED_TARGETS:
        if target.lower().startswith(blocked):
            raise HTTPException(status_code=400, detail="Cannot scan internal/private targets")
    return target


def calculate_risk_score(vulnerabilities: list) -> int:
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 2}
    return min(sum(weights.get(v.get("severity", "low").lower(), 1) for v in vulnerabilities), 100)


def run_full_scan_sync(scan_id: int, target: str, session_factory):
    db = session_factory()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan: return
        start_time = time.time()
        scan.status = "running"; scan.started_at = datetime.utcnow(); db.commit()
        
        scan.progress = 10; scan.current_step = "Port scanning"; db.commit()
        scan.ports_data = run_nmap_scan(target); scan.ports_count = len(scan.ports_data); scan.progress = 25; db.commit()
        
        scan.progress = 30; scan.current_step = "Technology detection"; db.commit()
        scan.technologies_data = run_whatweb_scan(target); scan.progress = 45; db.commit()
        
        scan.progress = 50; scan.current_step = "SSL/TLS check"; db.commit()
        scan.ssl_data = check_ssl_tls(target); scan.progress = 60; db.commit()
        
        scan.progress = 65; scan.current_step = "Security headers"; db.commit()
        scan.headers_data = check_security_headers(target); scan.progress = 75; db.commit()
        
        scan.progress = 80; scan.current_step = "Vulnerability scan"; db.commit()
        vulns = run_nuclei_scan(target); scan.vulnerabilities_data = vulns; scan.vulns_count = len(vulns); scan.progress = 90; db.commit()
        
        scan.progress = 92; scan.current_step = "Subdomain enum"; db.commit()
        scan.subdomains_data = run_subfinder_scan(target); scan.subdomains_count = len(scan.subdomains_data); scan.progress = 95; db.commit()
        
        scan.risk_score = calculate_risk_score(vulns); scan.progress = 100
        scan.status = "completed"; scan.completed_at = datetime.utcnow()
        scan.duration_seconds = round(time.time() - start_time, 2); db.commit()
    except Exception as e:
        if scan: scan.status = "failed"; scan.error_message = str(e); db.commit()
    finally: db.close()


@router.post("/scan")
@limiter.limit("5/hour")
async def start_scan(request: Request, scan_req: ScanRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    target = validate_target(scan_req.target)
    scan = Scan(user_id=current_user.id, target=target, scan_type=scan_req.scan_type, status="pending", progress=0)
    db.add(scan); db.commit(); db.refresh(scan)
    threading.Thread(target=run_full_scan_sync, args=(scan.id, target, SessionLocal)).start()
    return {"scan_id": scan.id, "target": target, "status": "scan_started"}


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan: raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(id=scan.id, target=scan.target, status=scan.status, progress=scan.progress, risk_score=scan.risk_score, risk_level="critical" if scan.risk_score >= 75 else "high" if scan.risk_score >= 50 else "medium" if scan.risk_score >= 25 else "low", ports=scan.ports_data or [], technologies=scan.technologies_data or [], vulnerabilities=scan.vulnerabilities_data or [], subdomains=scan.subdomains_data or [], ssl_info=scan.ssl_data or {}, headers_info=scan.headers_data or {}, started_at=scan.started_at, completed_at=scan.completed_at, duration_seconds=scan.duration_seconds, error_message=scan.error_message, created_at=scan.created_at)


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(20).all()
    return [ScanResponse(id=s.id, target=s.target, status=s.status, progress=s.progress, risk_score=s.risk_score, ports=s.ports_data or [], technologies=s.technologies_data or [], vulnerabilities=s.vulnerabilities_data or [], subdomains=s.subdomains_data or [], ssl_info=s.ssl_data or {}, headers_info=s.headers_data or {}, started_at=s.started_at, completed_at=s.completed_at, duration_seconds=s.duration_seconds, error_message=s.error_message, created_at=s.created_at) for s in scans]


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()
    total = len(scans)
    all_vulns = [v for s in scans if s.vulnerabilities_data for v in s.vulnerabilities_data]
    return DashboardStats(total_scans=total, completed_scans=sum(1 for s in scans if s.status == "completed"), failed_scans=sum(1 for s in scans if s.status == "failed"), running_scans=sum(1 for s in scans if s.status == "running"), total_vulnerabilities=len(all_vulns), critical_count=sum(1 for v in all_vulns if v.get("severity") == "critical"), high_count=sum(1 for v in all_vulns if v.get("severity") == "high"), medium_count=sum(1 for v in all_vulns if v.get("severity") == "medium"), low_count=sum(1 for v in all_vulns if v.get("severity") == "low"), average_risk_score=sum(s.risk_score or 0 for s in scans) / total if total > 0 else 0)


# ============ ADMIN ============

@router.get("/admin/users")
async def admin_get_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_admin: raise HTTPException(status_code=403, detail="Admin access required")
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "email": u.email, "is_active": u.is_active, "is_admin": u.is_admin, "created_at": u.created_at.isoformat() if u.created_at else None, "last_login": u.last_login.isoformat() if u.last_login else None} for u in users]


@router.get("/admin/scans")
async def admin_get_all_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_admin: raise HTTPException(status_code=403, detail="Admin access required")
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(50).all()
    return [{"id": s.id, "user_id": s.user_id, "target": s.target, "status": s.status, "progress": s.progress, "risk_score": s.risk_score, "ports_count": s.ports_count, "vulns_count": s.vulns_count, "created_at": s.created_at.isoformat() if s.created_at else None} for s in scans]


@router.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_admin: raise HTTPException(status_code=403, detail="Admin access required")
    if current_user.id == user_id: raise HTTPException(status_code=400, detail="Cannot delete yourself")
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    username = user.username
    db.query(Scan).filter(Scan.user_id == user_id).delete()
    db.delete(user); db.commit()
    return {"message": f"User '{username}' and all scans deleted"}
