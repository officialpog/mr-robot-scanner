"""
Mr. Robot Scanner - Main Application Entry Point
Advanced Vulnerability Intelligence Platform
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
from datetime import datetime

from config import settings
from database.database import engine, Base
from api import auth, scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Create all database tables on startup
    Base.metadata.create_all(bind=engine)
    print("=" * 60)
    print("🤖 Mr. Robot Scanner API Started")
    print("=" * 60)
    print(f"📡 API Docs: http://localhost:8000/api/docs")
    print(f"🔗 Base URL: http://localhost:8000")
    yield
    print("=" * 60)
    print("🛑 Mr. Robot Scanner API Shutting Down...")
    print("=" * 60)


app = FastAPI(
    title="Mr. Robot Scanner API",
    description="Advanced Vulnerability Intelligence Platform - Trust the scan. Fear the results.",
    version="2.4.1",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS - Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(auth.router, prefix=settings.API_V1_PREFIX, tags=["Authentication"])
app.include_router(scan.router, prefix=settings.API_V1_PREFIX, tags=["Scanning"])


@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": "Mr. Robot Scanner API",
        "version": "2.4.1",
        "status": "operational",
        "message": "Trust the scan. Fear the results.",
        "docs": "/api/docs",
        "endpoints": {
            "register": f"{settings.API_V1_PREFIX}/register",
            "login": f"{settings.API_V1_PREFIX}/login",
            "scan_public": f"{settings.API_V1_PREFIX}/scan/public",
            "scans": f"{settings.API_V1_PREFIX}/scans",
            "dashboard": f"{settings.API_V1_PREFIX}/dashboard/stats",
            "websocket": f"{settings.API_V1_PREFIX}/ws/scan/{{scan_id}}"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
