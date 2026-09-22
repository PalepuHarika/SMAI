from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class StaticFinding(BaseModel):
    id: str
    contract: str
    function: str
    line_start: int
    line_end: int
    category: str
    confidence: float
    message: str
    snippet: str
    severity: Optional[str] = "High"
    swc_id: Optional[str] = None

class CodeContext(BaseModel):
    contract_name: str
    function_name: str
    function_source: str
    line_start: int
    line_end: int
    modifiers: List[str] = Field(default_factory=list)
    state_variables: List[str] = Field(default_factory=list)
    external_calls: List[str] = Field(default_factory=list)
    candidate_slices: List[str] = Field(default_factory=list)
    surrounding_code: str = ""

class VerifiedVulnerability(BaseModel):
    finding_id: str = Field(..., description="Unique identifier for the finding")
    is_vulnerable: bool = Field(..., description="True if a genuine vulnerability, false if a false positive")
    verification_status: str = Field("CONFIRMED", description="CONFIRMED, REJECTED, or UNVERIFIED")
    vulnerability: str = Field(..., description="Vulnerability type/name")
    severity: str = Field(..., description="Severity: Critical, High, Medium, Low, Informational")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    static_confidence: Optional[float] = Field(None, description="Static analyzer original confidence")
    affected_lines: List[int] = Field(..., description="List of line numbers affected")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Array of evidence objects with 'function' and 'lines'")
    explanation: str = Field(..., description="Detailed explanation of the vulnerability")
    attack_scenario: str = Field(..., description="Step by step attack scenario, grounded only in the source")
    recommendation: str = Field(..., description="Concrete mitigation steps")
    original_code: str = Field(..., description="Original vulnerable code snippet")
    fixed_code: str = Field(..., description="Corrected code snippet")
    fallback_used: bool = Field(False, description="True if LLM verification failed and fallback was used")
    fallback_reason: Optional[str] = Field(None, description="Reason for fallback if used")
    model_used: Optional[str] = Field(None, description="Model used for inference")
    raw_response: Optional[str] = Field(None, description="Raw LLM response string")
    contract: Optional[str] = Field(None, description="Contract name")
    function: Optional[str] = Field(None, description="Enclosing function name")
    swc_id: Optional[str] = Field(None, description="SWC identifier")
    fix_verified: Optional[bool] = Field(None, description="True if rescanning fixed code confirms fix")
    static_evidence: Optional[str] = Field(None, description="Static code evidence snippet")
    retrieved_knowledge: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="RAG retrieved knowledge items")
    rag_similarity_score: Optional[float] = Field(None, description="Top RAG cosine similarity score")
    rag_explanation: Optional[str] = Field(None, description="Explanation of why RAG context supports finding")

class VulnerabilityReportPayload(BaseModel):
    analysis_id: str
    contract_name: str
    timestamp: str
    total_findings: int
    is_vulnerable: bool
    severity_counts: Dict[str, int]
    findings: List[VerifiedVulnerability]
    summary: str
    security_score: Optional[int] = Field(None, description="Security score from 0 to 100")
    risk_level: Optional[str] = Field(None, description="Risk level rating based on security score")
    source_code: Optional[str] = Field(None, description="Original Solidity source code")
