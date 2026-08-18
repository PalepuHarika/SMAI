import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from backend.core.finding import StaticFinding, CodeContext, VerifiedVulnerability, VulnerabilityReportPayload
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.analyzer.code_extractor import CodeContextExtractor
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.llm.reasoner import LLMReasoner

class SecurityPipeline:
    """
    End-to-End Security Pipeline:
    Solidity Code -> Static Analyzer -> Context Extractor -> RAG Retrieval -> LLM Reasoner -> Structured Report.
    """

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

    async def scan(self, source_code: str, contract_name: Optional[str] = None) -> VulnerabilityReportPayload:
        analysis_id = f"analysis-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # 1. Static Analysis
        raw_findings = self.analyzer.analyze(source_code, contract_name)
        
        verified_findings: List[VerifiedVulnerability] = []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

        # 2. Iterate through each static finding
        for finding in raw_findings:
            # Code Context Extraction
            context = self.extractor.extract(source_code, finding)
            
            # RAG Knowledge Retrieval
            knowledge = self.retriever.retrieve(finding, context, top_k=2)
            
            # LLM Reasoning & Verification
            verified = await self.reasoner.verify_finding(finding, context, knowledge)
            
            if verified.is_vulnerable:
                verified_findings.append(verified)
                sev = verified.severity
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts["Medium"] += 1

        # Summary Generation
        total_vulns = len(verified_findings)
        is_vuln = total_vulns > 0
        if not is_vuln:
            summary = f"Security analysis completed for '{contract_name or 'Contract'}'. No critical or high-risk vulnerabilities were identified by static analysis and LLM verification."
        else:
            crit = severity_counts.get("Critical", 0)
            high = severity_counts.get("High", 0)
            med = severity_counts.get("Medium", 0)
            low = severity_counts.get("Low", 0)
            summary = f"Security analysis identified {total_vulns} potential vulnerabilities ({crit} Critical, {high} High, {med} Medium, {low} Low) requiring attention."

        return VulnerabilityReportPayload(
            analysis_id=analysis_id,
            contract_name=contract_name or "Contract.sol",
            timestamp=timestamp,
            total_findings=total_vulns,
            is_vulnerable=is_vuln,
            severity_counts=severity_counts,
            findings=verified_findings,
            summary=summary
        )
