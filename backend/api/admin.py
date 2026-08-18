from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func
from backend.db.database import get_db
from backend.db.models import User, Analysis, VulnerabilityReport
from backend.core.security import require_admin

router = APIRouter(prefix="/api/admin", tags=["Admin"])

class UserSummary(BaseModel):
    id: str
    email: str
    role: str
    created_at: str
    scan_count: int

class AdminAnalytics(BaseModel):
    total_users: int
    total_analyses: int
    total_vulnerabilities: int
    severity_distribution: Dict[str, int]
    category_distribution: Dict[str, int]
    vulnerable_contracts_ratio: float

@router.get("/users", response_model=List[UserSummary])
async def get_all_users(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).options(selectinload(User.analyses)).order_by(User.created_at.desc())
    res = await db.execute(stmt)
    users = res.scalars().all()

    return [
        UserSummary(
            id=u.id,
            email=u.email,
            role=u.role,
            created_at=u.created_at.isoformat() if u.created_at else "",
            scan_count=len(u.analyses)
        )
        for u in users
    ]

@router.get("/analyses")
async def get_all_analyses(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Analysis)
        .options(selectinload(Analysis.user), selectinload(Analysis.report))
        .order_by(Analysis.created_at.desc())
    )
    res = await db.execute(stmt)
    analyses = res.scalars().all()

    return [
        {
            "id": a.id,
            "user_email": a.user.email if a.user else "Unknown",
            "contract_name": a.contract_name,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else "",
            "total_findings": a.report.total_findings if a.report else 0,
            "is_vulnerable": a.report.is_vulnerable if a.report else False,
            "severity_counts": a.report.severity_counts if a.report else {}
        }
        for a in analyses
    ]

@router.get("/analytics", response_model=AdminAnalytics)
async def get_admin_analytics(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    user_count_res = await db.execute(select(func.count(User.id)))
    total_users = user_count_res.scalar() or 0

    analysis_count_res = await db.execute(select(func.count(Analysis.id)))
    total_analyses = analysis_count_res.scalar() or 0

    reports_res = await db.execute(select(VulnerabilityReport))
    reports = reports_res.scalars().all()

    total_vulns = 0
    vulnerable_scans = 0
    severity_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    category_dist: Dict[str, int] = {}

    for r in reports:
        if r.is_vulnerable:
            vulnerable_scans += 1
        total_vulns += (r.total_findings or 0)
        if r.severity_counts:
            for k, v in r.severity_counts.items():
                if k in severity_dist:
                    severity_dist[k] += v
                else:
                    severity_dist[k] = severity_dist.get(k, 0) + v
        if r.verified_findings:
            for f in r.verified_findings:
                cat = f.get("vulnerability", "Other")
                category_dist[cat] = category_dist.get(cat, 0) + 1

    ratio = (vulnerable_scans / total_analyses) if total_analyses > 0 else 0.0

    return AdminAnalytics(
        total_users=total_users,
        total_analyses=total_analyses,
        total_vulnerabilities=total_vulns,
        severity_distribution=severity_dist,
        category_distribution=category_dist,
        vulnerable_contracts_ratio=round(ratio, 2)
    )
