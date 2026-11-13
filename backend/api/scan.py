from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, field_validator
from typing import Literal
from datetime import datetime
import ipaddress
import re
import asyncio
import logging

logger = logging.getLogger(__name__)

from database.database import get_db
from models.models import Scan, Vulnerability
from utils.auth import get_current_active_user
from scanners.whois_scanner import run_whois_scan
from scanners.dns_scanner import run_dns_scan
from scanners.ssl_scanner import run_ssl_scan
from scanners.headers_scanner import run_headers_scan
from scanners.tech_scanner import run_tech_scan
from scanners.vuln_analyzer import analyze_vulnerabilities
from scanners.assessment import collection_checks, collection_status

router = APIRouter(prefix="/api/scan", tags=["Scanning"])

class ScanRequest(BaseModel):
    target: str
    mode: Literal["light"] = "light"

    @field_validator("target")
    @classmethod
    def validate_target(cls, value):
        value = value.strip().lower().rstrip(".")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("Invalid domain")
        if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value):
            raise ValueError("Enter a domain or IP address without a scheme, path, or port")
        return value

def utc_string(value):
    return value.isoformat(timespec="seconds") + "Z" if value else None


@router.post("/light")
async def light_scan(
    req: ScanRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    target = req.target

    # Create scan record
    scan = Scan(
        user_id=current_user.id,
        target=target,
        status="running",
        mode="light"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        # Run reconnaissance scans concurrently
        whois_task = asyncio.to_thread(run_whois_scan, target)
        dns_task = asyncio.to_thread(run_dns_scan, target)
        ssl_task = asyncio.to_thread(run_ssl_scan, target)
        headers_task = asyncio.to_thread(run_headers_scan, target)
        tech_task = asyncio.to_thread(run_tech_scan, target)

        whois_result, dns_result, ssl_result, headers_result, tech_result = await asyncio.gather(
            whois_task, dns_task, ssl_task, headers_task, tech_task,
            return_exceptions=True
        )

        # Handle exceptions
        if isinstance(whois_result, Exception):
            whois_result = {"error": str(whois_result)}
        if isinstance(dns_result, Exception):
            dns_result = {"error": str(dns_result)}
        if isinstance(ssl_result, Exception):
            ssl_result = {"valid": False, "error": str(ssl_result)}
        if isinstance(headers_result, Exception):
            headers_result = {"error": str(headers_result), "missing": [], "present": []}
        if isinstance(tech_result, Exception):
            tech_result = [f"Error: {str(tech_result)}"]

        # Analyze vulnerabilities
        vulnerabilities = analyze_vulnerabilities(target, headers_result, ssl_result, tech_result)

        # Calculate risk score
        risk_scores = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        risk_score = sum(risk_scores.get(v["severity"], 0) for v in vulnerabilities)

        # Save vulnerabilities
        for vuln_data in vulnerabilities:
            vuln = Vulnerability(
                scan_id=scan.id,
                severity=vuln_data["severity"],
                title=vuln_data["title"],
                description=vuln_data["description"],
                solution=vuln_data.get("solution"),
                cve_id=vuln_data.get("cve_id")
            )
            db.add(vuln)

        # Update scan
        results = {
            "target": target,
            "whois": whois_result,
            "dns": dns_result,
            "ssl": ssl_result,
            "headers": headers_result,
            "technologies": tech_result,
            "vulnerabilities": vulnerabilities,
        }

        scan.completed_at = datetime.utcnow()
        checks = collection_checks(results)
        scan.status = collection_status(checks)
        results.update({
            "scan_id": scan.id, "status": scan.status, "mode": scan.mode,
            "created_at": utc_string(scan.created_at),
            "completed_at": utc_string(scan.completed_at),
            "checks": checks, "analysis_version": "2.0", "risk_score": risk_score,
            "score_note": "Local prioritization weights; not a CVSS score or a security guarantee.",
        })
        scan.risk_score = risk_score
        scan.results = results
        db.commit()

        return results

    except Exception:
        logger.exception("Scan failed")
        db.rollback()
        scan.completed_at = datetime.utcnow()
        scan.status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail="Scan failed; see backend logs for details")

@router.post("/local")
async def local_scan(
    req: ScanRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    raise HTTPException(status_code=501, detail="Local scanning tools are not implemented")

@router.get("/history")
def get_scan_history(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(50).all()
    return [
        {
            "id": s.id,
            "target": s.target,
            "status": s.status,
            "mode": s.mode,
            "risk_score": s.risk_score,
            "created_at": utc_string(s.created_at),
            "completed_at": utc_string(s.completed_at),
            "finding_count": len((s.results or {}).get("vulnerabilities", [])),
            "has_report": bool(s.results),
        }
        for s in scans
    ]


@router.get("/{scan_id}")
def get_scan_report(scan_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_active_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    results = dict(scan.results or {})
    results.update({"scan_id": scan.id, "target": scan.target, "status": scan.status,
                    "mode": scan.mode, "created_at": utc_string(scan.created_at),
                    "completed_at": utc_string(scan.completed_at), "risk_score": scan.risk_score})
    results.setdefault("checks", collection_checks(results))
    return results
