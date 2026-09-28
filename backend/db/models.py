import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, Text, ForeignKey, DateTime, JSON
from sqlalchemy.orm import relationship
from backend.db.database import Base

def gen_uuid():
    return uuid.uuid4().hex

class User(Base):
    __tablename__ = 'users'

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default='USER', nullable=False)  # 'USER' or 'ADMIN'
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analyses = relationship('Analysis', back_populates='user', cascade='all, delete-orphan')

class Analysis(Base):
    __tablename__ = 'analyses'

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    contract_name = Column(String(255), nullable=False)
    source_code = Column(Text, nullable=False)
    source_hash = Column(String(64), nullable=True)
    status = Column(String(50), default='COMPLETED')  # PENDING, RUNNING, COMPLETED, FAILED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship('User', back_populates='analyses')
    report = relationship('VulnerabilityReport', back_populates='analysis', uselist=False, cascade='all, delete-orphan')

class VulnerabilityReport(Base):
    __tablename__ = 'vulnerability_reports'

    id = Column(String(36), primary_key=True, default=gen_uuid)
    analysis_id = Column(String(36), ForeignKey('analyses.id'), unique=True, nullable=False)
    summary = Column(Text, nullable=False)
    total_findings = Column(Integer, default=0)
    is_vulnerable = Column(Boolean, default=False)
    severity_counts = Column(JSON, default=dict)
    raw_findings = Column(JSON, default=list)
    verified_findings = Column(JSON, default=list)
    source_hash = Column(String(64), nullable=True)
    report_hash = Column(String(64), nullable=True)
    findings_hash = Column(String(64), nullable=True)
    analyzer_version = Column(String(50), nullable=True)
    model_used = Column(String(100), nullable=True)
    analysis_mode = Column(String(50), nullable=True)
    compiler_version = Column(String(100), nullable=True)
    git_commit = Column(String(64), nullable=True)
    trust_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analysis = relationship('Analysis', back_populates='report')

