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
    source_hash: Optional[str] = None
    report_hash: Optional[str] = None

class ScanResponse(BaseModel):
    analysis_id: str
    status: str
    message: str

class VerifyFixRequest(BaseModel):
    analysis_id: str = Field(..., description="ID of the analysis containing the target finding")
    finding_id: Optional[str] = Field(None, description="Unique ID of the finding being fixed")
    vulnerability_category: Optional[str] = Field(None, description="Category of the target finding if finding_id is not provided")
    fixed_code: str = Field(..., description="Proposed Solidity fixed code")

class VerifyFixResponse(BaseModel):
    fix_verified: bool
    category_resolved: bool
    has_new_severe: bool
    syntax_valid: bool
    original_category: str
    remaining_findings: List[Dict[str, Any]] = Field(default_factory=list)
    new_severe_findings: List[Dict[str, Any]] = Field(default_factory=list)
    verification_reason: str
    compiler_verification: str = "not_performed"


async def process_analysis_background(analysis_id: str, source_code: str, contract_name: str, mode: str = "C", user_id: Optional[str] = None):
    try:
        # Run the core security pipeline
        report_payload = await pipeline.scan(source_code, contract_name, mode=mode, user_id=user_id)
        
        async with AsyncSessionLocal() as db:
            stmt = select(Analysis).where(Analysis.id == analysis_id)
            res = await db.execute(stmt)
            analysis = res.scalar_one_or_none()
            if analysis:
                analysis.status = "COMPLETED"
                analysis.source_hash = report_payload.source_hash
                report = VulnerabilityReport(
                    analysis_id=analysis.id,
                    summary=report_payload.summary,
                    total_findings=report_payload.total_findings,
                    is_vulnerable=report_payload.is_vulnerable,
                    severity_counts=report_payload.severity_counts,
                    raw_findings=[],
                    verified_findings=[f.model_dump() for f in report_payload.findings],
                    source_hash=report_payload.source_hash,
                    report_hash=report_payload.report_hash,
                    findings_hash=report_payload.findings_hash,
                    analyzer_version=report_payload.analyzer_version,
                    model_used=report_payload.model_used,
                    analysis_mode=report_payload.analysis_mode,
                    compiler_version=report_payload.compiler_version,
                    git_commit=report_payload.git_commit,
                    trust_metadata={
                        "source_keccak256": report_payload.source_keccak256,
                        "findings_merkle_root": report_payload.findings_merkle_root,
                        "rag_version": report_payload.rag_version,
                        "analysis_timestamp": report_payload.analysis_timestamp,
                        "user_id": analysis.user_id,
                    }
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
    
    from backend.core.integrity import hash_source_sha256
    initial_source_hash = hash_source_sha256(req.source_code)

    # Persist initial pending state in DB
    analysis = Analysis(
        id=analysis_id,
        user_id=current_user.id,
        contract_name=req.contract_name or "Contract.sol",
        source_code=req.source_code,
        source_hash=initial_source_hash,
        status="PENDING"
    )
    db.add(analysis)
    await db.commit()

    background_tasks.add_task(process_analysis_background, analysis_id, req.source_code, req.contract_name, req.mode or "C", current_user.id)

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
            severity_counts=rep.severity_counts if rep and rep.severity_counts else {},
            source_hash=rep.source_hash if (rep and rep.source_hash) else a.source_hash,
            report_hash=rep.report_hash if (rep and rep.report_hash) else None
        ))
    return items

@router.post("/verify-fix", response_model=VerifyFixResponse)
async def verify_fix(
    req: VerifyFixRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Analysis)
        .where(Analysis.id == req.analysis_id)
        .options(selectinload(Analysis.report))
    )
    res = await db.execute(stmt)
    analysis = res.scalar_one_or_none()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
        )

    # RBAC check: Only owner or ADMIN can verify fixes
    if analysis.user_id != current_user.id and current_user.role != 'ADMIN':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this analysis report"
        )

    rep = analysis.report
    if not rep:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report data unavailable"
        )

    verified_findings = rep.verified_findings or []
    target_finding = None

    for f in verified_findings:
        f_id = f.get("finding_id") or f.get("id")
        if req.finding_id and f_id == req.finding_id:
            target_finding = f
            break
        elif not req.finding_id and req.vulnerability_category:
            cat = f.get("vulnerability") or f.get("category") or ""
            if cat.strip().lower().replace("_", "-") == req.vulnerability_category.strip().lower().replace("_", "-"):
                target_finding = f
                break

    if target_finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target finding '{req.finding_id or req.vulnerability_category}' not found in report"
        )

    orig_category = (
        target_finding.get("vulnerability")
        or target_finding.get("category")
        or ""
    )

    from backend.llm.reasoner import verify_fix_details
    verification_result = verify_fix_details(req.fixed_code, orig_category)

    # Persist the latest verification result in the report finding
    target_finding["fix_verified"] = verification_result["fix_verified"]
    target_finding["fix_verification_reason"] = verification_result["verification_reason"]
    rep.verified_findings = list(verified_findings)
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(rep, "verified_findings")
    await db.commit()

    return VerifyFixResponse(
        fix_verified=verification_result["fix_verified"],
        category_resolved=verification_result["category_resolved"],
        has_new_severe=verification_result["has_new_severe"],
        syntax_valid=verification_result["syntax_valid"],
        original_category=orig_category,
        remaining_findings=verification_result["remaining_findings"],
        new_severe_findings=verification_result["new_severe_findings"],
        verification_reason=verification_result["verification_reason"],
        compiler_verification=verification_result.get("compiler_verification", "not_performed"),
    )

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

    trust_meta = rep.trust_metadata or {}
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
        source_code=analysis.source_code,
        source_hash=rep.source_hash or analysis.source_hash,
        source_keccak256=trust_meta.get("source_keccak256"),
        report_hash=rep.report_hash,
        findings_hash=rep.findings_hash,
        findings_merkle_root=trust_meta.get("findings_merkle_root"),
        analyzer_version=rep.analyzer_version,
        analysis_timestamp=trust_meta.get("analysis_timestamp") or (analysis.created_at.isoformat() if analysis.created_at else ""),
        model_used=rep.model_used,
        analysis_mode=rep.analysis_mode,
        rag_version=trust_meta.get("rag_version"),
        compiler_version=rep.compiler_version,
        git_commit=rep.git_commit,
        user_id=analysis.user_id
    )

