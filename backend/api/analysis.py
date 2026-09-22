import uuid
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from backend.db.database import get_db, AsyncSessionLocal
from backend.db.models import User, Analysis, VulnerabilityReport
from backend.core.security import get_current_user
from backend.pipeline import SecurityPipeline
from backend.core.finding import VulnerabilityReportPayload

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])
pipeline = SecurityPipeline()

class ScanRequest(BaseModel):
    contract_name: Optional[str] = "Contract.sol"
    source_code: str = Field(..., min_length=1)
    mode: Optional[str] = "C"

class AnalysisListItem(BaseModel):
    id: str
    contract_name: str
    status: str
    created_at: str
    total_findings: int
    is_vulnerable: bool
    severity_counts: Dict[str, int]

class ScanResponse(BaseModel):
    analysis_id: str
    status: str
    message: str

async def process_analysis_background(analysis_id: str, source_code: str, contract_name: str, mode: str = "C"):
    try:
        # Run the core security pipeline
        report_payload = await pipeline.scan(source_code, contract_name, mode=mode)
        
        async with AsyncSessionLocal() as db:
            stmt = select(Analysis).where(Analysis.id == analysis_id)
            res = await db.execute(stmt)
            analysis = res.scalar_one_or_none()
            if analysis:
                analysis.status = "COMPLETED"
                report = VulnerabilityReport(
                    analysis_id=analysis.id,
                    summary=report_payload.summary,
                    total_findings=report_payload.total_findings,
                    is_vulnerable=report_payload.is_vulnerable,
                    severity_counts=report_payload.severity_counts,
                    raw_findings=[],
                    verified_findings=[f.model_dump() for f in report_payload.findings]
                )
                db.add(report)
                await db.commit()
    except Exception as e:
        print(f"PIPELINE EXCEPTION: {repr(e)}")
        async with AsyncSessionLocal() as db:
            stmt = select(Analysis).where(Analysis.id == analysis_id)
            res = await db.execute(stmt)
            analysis = res.scalar_one_or_none()
            if analysis:
                analysis.status = "FAILED"
                await db.commit()

@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_analysis(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if len(req.source_code.encode('utf-8')) > 500_000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Solidity source exceeds maximum supported size (500KB)"
        )

    analysis_id = f"analysis-{uuid.uuid4().hex[:12]}"
    
    # Persist initial pending state in DB
    analysis = Analysis(
        id=analysis_id,
        user_id=current_user.id,
        contract_name=req.contract_name or "Contract.sol",
        source_code=req.source_code,
        status="PENDING"
    )
    db.add(analysis)
    await db.commit()

    background_tasks.add_task(process_analysis_background, analysis_id, req.source_code, req.contract_name, req.mode or "C")

    return ScanResponse(
        analysis_id=analysis_id,
        status="PENDING",
        message="Analysis started in the background."
    )

@router.get("/history", response_model=List[AnalysisListItem])
async def get_analysis_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Analysis)
        .where(Analysis.user_id == current_user.id)
        .options(selectinload(Analysis.report))
        .order_by(Analysis.created_at.desc())
    )
    res = await db.execute(stmt)
    analyses = res.scalars().all()

    items = []
    for a in analyses:
        rep = a.report
        items.append(AnalysisListItem(
            id=a.id,
            contract_name=a.contract_name,
            status=a.status,
            created_at=a.created_at.isoformat() if a.created_at else "",
            total_findings=rep.total_findings if rep else 0,
            is_vulnerable=rep.is_vulnerable if rep else False,
            severity_counts=rep.severity_counts if rep and rep.severity_counts else {}
        ))
    return items

@router.get("/{analysis_id}")
async def get_analysis_by_id(
    analysis_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Analysis)
        .where(Analysis.id == analysis_id)
        .options(selectinload(Analysis.report))
    )
    res = await db.execute(stmt)
    analysis = res.scalar_one_or_none()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
        )

    # RBAC check: Only owner or ADMIN can view
    if analysis.user_id != current_user.id and current_user.role != 'ADMIN':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this analysis report"
        )

    if analysis.status == "PENDING":
        return {"status": "PENDING", "message": "Analysis is still in progress."}
    if analysis.status == "FAILED":
        return {"status": "FAILED", "message": "Analysis failed during execution."}

    rep = analysis.report
    if not rep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report data unavailable")

    from backend.pipeline import calculate_security_score
    from backend.core.finding import VerifiedVulnerability
    findings_list = [VerifiedVulnerability(**f) if isinstance(f, dict) else f for f in (rep.verified_findings or [])]
    score, risk = calculate_security_score(findings_list)

    return VulnerabilityReportPayload(
        analysis_id=analysis.id,
        contract_name=analysis.contract_name,
        timestamp=analysis.created_at.isoformat() if analysis.created_at else "",
        total_findings=rep.total_findings,
        is_vulnerable=rep.is_vulnerable,
        severity_counts=rep.severity_counts or {},
        findings=findings_list,
        summary=rep.summary,
        security_score=score,
        risk_level=risk,
        source_code=analysis.source_code
    )
