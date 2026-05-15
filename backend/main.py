"""
Mr. Robot Scanner - Main Application Entry Point
Advanced Vulnerability Intelligence Platform
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn
from datetime import datetime

from config import settings
from database.database import engine, Base
from api import auth, scan

# Rate limiter: 100 requests per hour per IP
limiter = Limiter(key_func=get_remote_address, default_limits=["100/hour"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    Base.metadata.create_all(bind=engine)
    print("=" * 60)
    print("🤖 Mr. Robot Scanner API Started")
    print(f"📡 API Docs: http://localhost:8000/api/docs")
    print(f"🛡️ Rate Limits: 100 req/hr | 5 scans/hr | 10 register/hr | 20 login/hr")
    print("=" * 60)
    yield
    print("🛑 Shutting down...")


app = FastAPI(
    title="Mr. Robot Scanner API",
    description="Advanced Vulnerability Intelligence Platform",
    version="2.4.1",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router, prefix=settings.API_V1_PREFIX, tags=["Authentication"])
app.include_router(scan.router, prefix=settings.API_V1_PREFIX, tags=["Scanning"])


@app.get("/")
async def root():
    return {
        "name": "Mr. Robot Scanner API",
        "version": "2.4.1",
        "status": "operational",
        "security": {
            "rate_limiting": "100 requests/hour",
            "scan_limit": "5 scans/hour per user",
            "register_limit": "10 registrations/hour",
            "login_limit": "20 logins/hour",
            "authentication": "JWT Bearer tokens",
            "password_hashing": "PBKDF2 SHA-256 + salt"
        },
        "endpoints": {
            "register": f"{settings.API_V1_PREFIX}/register",
            "login": f"{settings.API_V1_PREFIX}/login",
            "scan": f"{settings.API_V1_PREFIX}/scan",
            "scans": f"{settings.API_V1_PREFIX}/scans",
            "dashboard": f"{settings.API_V1_PREFIX}/dashboard/stats",
            "admin": f"{settings.API_V1_PREFIX}/admin/users"
        }
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
