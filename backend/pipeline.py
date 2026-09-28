import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from backend.core.finding import StaticFinding, CodeContext, VerifiedVulnerability, VulnerabilityReportPayload
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.analyzer.code_extractor import CodeContextExtractor
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.llm.reasoner import LLMReasoner
from backend.core.integrity import (
    hash_source_sha256,
    hash_source_keccak256,
    compute_finding_hash,
    compute_findings_hash,
    compute_findings_merkle_root,
    compute_report_hash,
    extract_solidity_pragma,
    get_git_commit,
    get_knowledge_base_version,
    ANALYZER_VERSION
)

def calculate_security_score(findings: List[VerifiedVulnerability]) -> Tuple[int, str]:
    score = 100.0
    deduction_weights = {
        "Critical": 25.0,
        "High": 15.0,
        "Medium": 8.0,
        "Low": 3.0,
        "Informational": 1.0,
    }

    # Strict maximum penalty that can be incurred per severity tier
    deduction_caps = {
        "Critical": 100.0,
        "High": 100.0,
        "Medium": 30.0,
        "Low": 20.0,
        "Informational": 10.0,
    }

    tier_deductions = {
        "Critical": 0.0,
        "High": 0.0,
        "Medium": 0.0,
        "Low": 0.0,
        "Informational": 0.0,
    }

    max_severity_weight = 0
    highest_severity = "Informational"

    for f in findings:
        conf = f.confidence if f.confidence is not None else 0.8
        
        # Safely handle NaN or invalid types
        if not isinstance(conf, (int, float)) or conf != conf:
            conf = 0.8
        conf = max(0.0, min(1.0, float(conf)))
        
        weight = deduction_weights.get(f.severity, 8.0)
        
        if f.verification_status in ["CONFIRMED", "UNVERIFIED"]:
            if f.severity in tier_deductions:
                tier_deductions[f.severity] += weight * conf
            
            if weight > max_severity_weight:
                max_severity_weight = weight
                highest_severity = str(f.severity).title()

    # Apply the caps and deduct from base score
    for sev, total_deduction in tier_deductions.items():
        cap = deduction_caps.get(sev, 100.0)
        score -= min(total_deduction, cap)

    final_score = max(0, min(100, int(round(score))))
    
    if final_score >= 90:
        base_risk = "Low Risk"
    elif final_score >= 70:
        base_risk = "Moderate Risk"
    elif final_score >= 40:
        base_risk = "High Risk"
    else:
        base_risk = "Critical Risk"

    risk_hierarchy = {
        "Critical Risk": 4,
        "High Risk": 3,
        "Moderate Risk": 2,
        "Low Risk": 1
    }
    
    severity_floor = {
        "Critical": "Critical Risk",
        "High": "High Risk",
        "Medium": "Moderate Risk",
        "Low": "Low Risk",
        "Informational": "Low Risk"
    }

    floor_risk = severity_floor.get(highest_severity, "Low Risk")
    
    if risk_hierarchy.get(floor_risk, 1) > risk_hierarchy.get(base_risk, 1):
        risk_level = floor_risk
    else:
        risk_level = base_risk

    return final_score, risk_level

class SecurityPipeline:
    def __init__(
        self,
        analyzer: Optional[SolidityStaticAnalyzer] = None,
        extractor: Optional[CodeContextExtractor] = None,
        kb: Optional[SecurityKnowledgeBase] = None,
        retriever: Optional[RAGRetriever] = None,
        reasoner: Optional[LLMReasoner] = None
    ):
        self.analyzer = analyzer or SolidityStaticAnalyzer()
        self.extractor = extractor or CodeContextExtractor()
        self.kb = kb or SecurityKnowledgeBase()
        self.retriever = retriever or RAGRetriever(self.kb)
        self.reasoner = reasoner or LLMReasoner()

    async def scan(
        self,
        source_code: str,
        contract_name: Optional[str] = None,
        mode: str = "hybrid",
        user_id: Optional[str] = None
    ) -> VulnerabilityReportPayload:
        analysis_id = f"analysis-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Compute source integrity hashes and extract compiler pragma
        source_hash = hash_source_sha256(source_code)
        source_keccak256 = hash_source_keccak256(source_code)
        compiler_version = extract_solidity_pragma(source_code)

        # Normalize mode: canonical modes are 'rag', 'ai', 'hybrid'
        # Legacy aliases: A -> rag, B -> ai, C -> hybrid
        mode_str = (mode or "hybrid").strip().lower()
        mode_mapping = {
            "a": "rag",
            "b": "ai",
            "c": "hybrid",
            "rag": "rag",
            "ai": "ai",
            "hybrid": "hybrid"
        }
        normalized_mode = mode_mapping.get(mode_str, "hybrid")
        
        raw_findings = self.analyzer.analyze(source_code, contract_name)
        verified_findings: List[VerifiedVulnerability] = []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

        if normalized_mode == "rag":
            for finding in raw_findings:
                context = self.extractor.extract(source_code, finding)
                knowledge = self.retriever.retrieve(finding, context, top_k=2)
                
                if knowledge:
                    explanation = f"**RAG Context**: {knowledge[0].get('description', '')}"
                    recommendation = knowledge[0].get('mitigation', '')
                    scenario = knowledge[0].get('exploit_pattern', '')
                    rag_score, rag_explain = self.retriever.get_explainability_summary(knowledge)
                else:
                    explanation = f"Static analyzer detection: {finding.message}"
                    recommendation = f"Review and refactor function '{finding.function}' to address {finding.category}."
                    scenario = "Rule-based heuristic pattern flagged in static AST/regex analysis."
                    rag_score, rag_explain = None, None

                sev = finding.severity or "High"
                calibrated_conf = round(min(0.90, max(0.60, finding.confidence)), 2)
                v_status = "CONFIRMED" if (isinstance(mode, str) and mode.strip().upper() == "A") else "UNVERIFIED"
                verified = VerifiedVulnerability(
                    finding_id=finding.id,
                    is_vulnerable=True,
                    verification_status=v_status,
                    vulnerability=finding.category,
                    severity=sev,
                    confidence=calibrated_conf,
                    static_confidence=finding.confidence,
                    affected_lines=list(range(finding.line_start, finding.line_end + 1)),
                    evidence=[{"function": finding.function, "lines": list(range(finding.line_start, finding.line_end + 1))}],
                    explanation=explanation,
                    attack_scenario=scenario,
                    recommendation=recommendation,
                    original_code=finding.snippet,
                    fixed_code="Manual fix required (AI not used)",
                    fallback_used=False,
                    model_used="RAG Only (No AI)",
                    contract=finding.contract,
                    function=finding.function,
                    swc_id=finding.swc_id,
                    static_evidence=finding.snippet,
                    retrieved_knowledge=knowledge,
                    rag_similarity_score=rag_score,
                    rag_explanation=rag_explain
                )
                verified_findings.append(verified)
        else:
            async def verify_single_finding(finding):
                context = self.extractor.extract(source_code, finding)
                knowledge = None
                if normalized_mode == "hybrid":
                    knowledge = self.retriever.retrieve(finding, context, top_k=2)
                return await self.reasoner.verify_finding(finding, context, knowledge)
            
            results = []
            for f in raw_findings:
                result = await verify_single_finding(f)
                results.append(result)
            
            for verified in results:
                if verified.is_vulnerable or verified.verification_status in ["CONFIRMED", "UNVERIFIED"]:
                    if normalized_mode == "ai":
                         verified.retrieved_knowledge = []
                         verified.rag_similarity_score = None
                         verified.rag_explanation = None
                    verified_findings.append(verified)

        for verified in verified_findings:
            sev = str(verified.severity).title()
            if sev not in severity_counts:
                sev = "Medium"
            verified.severity = sev
            severity_counts[sev] += 1

        total_vulns = len(verified_findings)
        is_vuln = total_vulns > 0
        security_score, risk_level = calculate_security_score(verified_findings)

        if not is_vuln:
            summary = f"Security analysis completed for '{contract_name or 'Contract'}'. Security Score: {security_score}/100 ({risk_level}). No security vulnerabilities were identified."
        else:
            crit = severity_counts.get("Critical", 0)
            high = severity_counts.get("High", 0)
            med = severity_counts.get("Medium", 0)
            low = severity_counts.get("Low", 0)
            summary = f"Security analysis identified {total_vulns} findings ({crit} Critical, {high} High, {med} Medium, {low} Low). Security Score: {security_score}/100 ({risk_level})."

        # Compute deterministic hashes for findings and full report
        for verified in verified_findings:
            verified.finding_hash = compute_finding_hash(verified)

        findings_hash = compute_findings_hash(verified_findings)
        findings_merkle_root = compute_findings_merkle_root(verified_findings)
        report_hash = compute_report_hash(
            source_hash=source_hash,
            findings_hash=findings_hash,
            security_score=security_score,
            risk_level=risk_level,
            analysis_mode=normalized_mode
        )

        if normalized_mode == "rag":
            model_used = "RAG Only (No AI)"
        else:
            model_used = getattr(self.reasoner, "model", "Qwen2.5-Coder")

        return VulnerabilityReportPayload(
            analysis_id=analysis_id,
            contract_name=contract_name or "Contract.sol",
            timestamp=timestamp,
            total_findings=total_vulns,
            is_vulnerable=is_vuln,
            severity_counts=severity_counts,
            findings=verified_findings,
            summary=summary,
            security_score=security_score,
            risk_level=risk_level,
            source_code=source_code,
            source_hash=source_hash,
            source_keccak256=source_keccak256,
            report_hash=report_hash,
            findings_hash=findings_hash,
            findings_merkle_root=findings_merkle_root,
            analyzer_version=ANALYZER_VERSION,
            analysis_timestamp=timestamp,
            model_used=model_used,
            analysis_mode=normalized_mode,
            rag_version=get_knowledge_base_version(),
            compiler_version=compiler_version,
            git_commit=get_git_commit(),
            user_id=user_id
        )

