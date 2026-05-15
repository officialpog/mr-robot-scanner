from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from config import settings
from database.database import engine, Base
from api import auth, scan

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    print("🤖 Mr. Robot Scanner API started")
    print(f"📡 API Docs: http://localhost:8000/api/docs")
    yield
    print("🛑 Shutting down...")

app = FastAPI(
    title="Mr. Robot Scanner API",
    description="Advanced Vulnerability Intelligence Platform - Trust the scan. Fear the results.",
    version="2.4.1",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.API_V1_PREFIX, tags=["Authentication"])
app.include_router(scan.router, prefix=settings.API_V1_PREFIX, tags=["Scanning"])

@app.get("/")
async def root():
    return {
        "name": "Mr. Robot Scanner API",
        "version": "2.4.1",
        "status": "operational",
        "endpoints": {
            "docs": "/api/docs",
            "register": f"{settings.API_V1_PREFIX}/register",
            "login": f"{settings.API_V1_PREFIX}/login",
            "scan": f"{settings.API_V1_PREFIX}/scan/public",
            "scans": f"{settings.API_V1_PREFIX}/scans",
            "dashboard": f"{settings.API_V1_PREFIX}/dashboard/stats",
            "websocket": f"{settings.API_V1_PREFIX}/ws/scan/{{scan_id}}"
        }
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)