import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from backend.core.finding import StaticFinding, CodeContext, VerifiedVulnerability, VulnerabilityReportPayload
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.analyzer.code_extractor import CodeContextExtractor
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.llm.reasoner import LLMReasoner

def calculate_security_score(findings: List[VerifiedVulnerability]) -> Tuple[int, str]:
    score = 100.0
    deduction_weights = {
        "Critical": 25.0,
        "High": 15.0,
        "Medium": 8.0,
        "Low": 3.0,
        "Informational": 1.0,
    }

    for f in findings:
        conf = f.confidence if f.confidence is not None else 0.8
        if f.verification_status == "CONFIRMED":
            weight = deduction_weights.get(f.severity, 8.0)
            score -= weight * conf
        elif f.verification_status == "UNVERIFIED":
            score -= 3.0 * conf

    final_score = max(0, min(100, int(round(score))))
    if final_score >= 90:
        risk_level = "Low Risk"
    elif final_score >= 70:
        risk_level = "Moderate Risk"
    elif final_score >= 40:
        risk_level = "High Risk"
    else:
        risk_level = "Critical Risk"

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

    async def scan(self, source_code: str, contract_name: Optional[str] = None, mode: str = "C") -> VulnerabilityReportPayload:
        # mode A: static only
        # mode B: static + LLM
        # mode C: static + RAG + LLM
        analysis_id = f"analysis-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        raw_findings = self.analyzer.analyze(source_code, contract_name)
        verified_findings: List[VerifiedVulnerability] = []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

        for finding in raw_findings:
            if mode == "A":
                # Static only - use finding severity from analyzer
                sev = finding.severity or "High"
                verified = VerifiedVulnerability(
                    finding_id=finding.id,
                    is_vulnerable=True,
                    verification_status="CONFIRMED",
                    vulnerability=finding.category,
                    severity=sev,
                    confidence=finding.confidence,
                    static_confidence=finding.confidence,
                    affected_lines=list(range(finding.line_start, finding.line_end + 1)),
                    evidence=[{"function": finding.function, "lines": list(range(finding.line_start, finding.line_end + 1))}],
                    explanation=f"Static analyzer flag: {finding.message}",
                    attack_scenario="Static analysis detected a high-risk security pattern without LLM execution.",
                    recommendation=f"Review and refactor function '{finding.function}' to address {finding.category}.",
                    original_code=finding.snippet,
                    fixed_code="",
                    fallback_used=False,
                    contract=finding.contract,
                    function=finding.function,
                    swc_id=finding.swc_id,
                    static_evidence=finding.snippet
                )
            else:
                context = self.extractor.extract(source_code, finding)
                knowledge = None
                if mode == "C":
                    knowledge = self.retriever.retrieve(finding, context, top_k=2)
                
                verified = await self.reasoner.verify_finding(finding, context, knowledge)
            
            if verified.is_vulnerable or verified.verification_status == "CONFIRMED":
                verified_findings.append(verified)
                sev = verified.severity
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts["Medium"] += 1
            elif verified.verification_status == "UNVERIFIED":
                verified_findings.append(verified)

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
            risk_level=risk_level
        )
