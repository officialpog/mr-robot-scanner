"""
Mr. Robot Scanner - Database Models
SQLAlchemy ORM models for Users and Scans.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, Float, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from database.database import Base


class User(Base):
    """User model for authentication"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(username='{self.username}')>"


class Scan(Base):
    """Scan model for storing scan results"""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    # Target
    target = Column(String(255), nullable=False, index=True)
    scan_type = Column(String(50), default="full")
    
    # Status
    status = Column(String(20), default="pending")
    progress = Column(Integer, default=0)
    current_step = Column(String(100), nullable=True)
    
    # Risk
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="unknown")
    
    # Results (JSON)
    ports_data = Column(JSON, default=list)
    technologies_data = Column(JSON, default=list)
    vulnerabilities_data = Column(JSON, default=list)
    ssl_data = Column(JSON, default=dict)
    subdomains_data = Column(JSON, default=list)
    headers_data = Column(JSON, default=dict)
    
    # Stats
    ports_count = Column(Integer, default=0)
    vulns_count = Column(Integer, default=0)
    subdomains_count = Column(Integer, default=0)
    duration_seconds = Column(Float, default=0.0)
    
    # Error
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="scans")

    def __repr__(self):
        return f"<Scan(id={self.id}, target='{self.target}', status='{self.status}')>"