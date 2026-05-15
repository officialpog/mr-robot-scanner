"""
Mr. Robot Scanner - Pydantic Schemas
Request/Response models for API validation and serialization.
"""

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import re


# ============ AUTHENTICATION SCHEMAS ============

class UserCreate(BaseModel):
    """Schema for user registration"""
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_]+$",
        example="elliot_alderson"
    )
    email: EmailStr = Field(..., example="elliot@allsafe.com")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        example="MrR0b0t!2024"
    )

    @validator("password")
    def validate_password_strength(cls, value: str) -> str:
        """Ensure password meets security requirements"""
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one number")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise ValueError("Password must contain at least one special character")
        return value


class UserLogin(BaseModel):
    """Schema for user login"""
    username: str = Field(..., example="elliot_alderson")
    password: str = Field(..., example="MrR0b0t!2024")


class Token(BaseModel):
    """Schema for JWT token response"""
    access_token: str
    token_type: str = "bearer"
    username: str
    expires_in: int = 3600


class UserResponse(BaseModel):
    """Schema for user data response"""
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


# ============ SCANNING SCHEMAS ============

class ScanRequest(BaseModel):
    """Schema for scan request"""
    target: str = Field(
        ...,
        min_length=1,
        max_length=255,
        example="example.com",
        description="Domain or IP address to scan"
    )
    scan_type: str = Field(
        default="full",
        pattern=r"^(full|quick|ports|vulns|ssl|headers)$",
        description="Type of scan to perform"
    )

    @validator("target")
    def validate_target(cls, value: str) -> str:
        """Basic target validation"""
        value = value.strip().lower()
        # Remove protocol prefix if present
        value = re.sub(r"^https?://", "", value)
        # Remove trailing slash
        value = value.rstrip("/")
        if not value:
            raise ValueError("Target cannot be empty")
        if len(value) > 255:
            raise ValueError("Target too long (max 255 characters)")
        return value


class PortInfo(BaseModel):
    """Schema for port information"""
    port: str = Field(..., example="443/tcp")
    service: str = Field(..., example="https")
    status: str = Field(..., example="open")
    version: Optional[str] = Field(None, example="nginx 1.18.0")


class VulnerabilityInfo(BaseModel):
    """Schema for vulnerability information"""
    severity: str = Field(..., example="critical")
    title: str = Field(..., example="Remote Code Execution")
    description: str = Field(..., example="Vulnerability allows unauthorized code execution")
    cve_id: Optional[str] = Field(None, example="CVE-2023-1234")
    cvss_score: Optional[float] = Field(None, ge=0, le=10, example=9.8)
    solution: Optional[str] = Field(None, example="Update to version 2.0 or later")
    reference: Optional[str] = Field(None, example="https://nvd.nist.gov/vuln/detail/CVE-2023-1234")


class TechnologyInfo(BaseModel):
    """Schema for technology detection"""
    name: str = Field(..., example="nginx")
    version: Optional[str] = Field(None, example="1.18.0")
    category: Optional[str] = Field(None, example="web-server")


class SSLInfo(BaseModel):
    """Schema for SSL/TLS information"""
    valid: bool = True
    issuer: Optional[Dict[str, str]] = None
    subject: Optional[Dict[str, str]] = None
    expires_in_days: Optional[int] = None
    expiry_date: Optional[str] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    warnings: List[str] = []


class HeadersInfo(BaseModel):
    """Schema for security headers information"""
    grade: str = "N/A"
    score: int = 0
    total_headers: int = 0
    present_headers: int = 0
    missing_headers: List[str] = []
    missing_critical: List[str] = []
    headers: Dict[str, Optional[str]] = {}
    summary: str = ""


class ScanResponse(BaseModel):
    """Schema for scan result response"""
    id: int
    target: str
    status: str
    progress: int = 0
    risk_score: int = 0
    risk_level: str = "unknown"
    ports: List[PortInfo] = []
    technologies: List[TechnologyInfo] = []
    vulnerabilities: List[VulnerabilityInfo] = []
    subdomains: List[str] = []
    ssl_info: Optional[Dict[str, Any]] = {}
    headers_info: Optional[Dict[str, Any]] = {}
    dns_info: Optional[Dict[str, Any]] = {}
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Schema for list of scans"""
    total: int
    scans: List[ScanResponse]
    page: int = 1
    per_page: int = 20


class DashboardStats(BaseModel):
    """Schema for dashboard statistics"""
    total_scans: int = 0
    completed_scans: int = 0
    failed_scans: int = 0
    running_scans: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    average_risk_score: float = 0.0
    recent_scans: List[ScanResponse] = []


class WebSocketMessage(BaseModel):
    """Schema for WebSocket messages"""
    type: str  # progress, status, error, complete
    scan_id: int
    data: Dict[str, Any] = {}
    timestamp: datetime = Field(default_factory=datetime.utcnow)