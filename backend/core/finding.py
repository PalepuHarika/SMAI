from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class StaticFinding(BaseModel):
    id: str = Field(..., description="Unique finding identifier")
    contract: str = Field(..., description="Target smart contract name")
    function: str = Field(..., description="Target function name or global scope")
    line_start: int = Field(..., description="Starting line number of finding (1-indexed)")
    line_end: int = Field(..., description="Ending line number of finding (1-indexed)")
    category: str = Field(..., description="Vulnerability category, e.g. reentrancy, unchecked-call")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score of static detector between 0.0 and 1.0")
    message: str = Field(..., description="Detailed detector message explaining the suspicious pattern")
    snippet: Optional[str] = Field(None, description="Code snippet around the finding")

class CodeContext(BaseModel):
    contract_name: str
    function_name: str
    function_source: str
    line_start: int
    line_end: int
    modifiers: List[str] = Field(default_factory=list)
    state_variables: List[str] = Field(default_factory=list)
    external_calls: List[str] = Field(default_factory=list)
    surrounding_code: str = ""

class VerifiedVulnerability(BaseModel):
    finding_id: str
    is_vulnerable: bool
    vulnerability: str
    severity: str = Field(..., description="Critical, High, Medium, Low, or Informational")
    confidence: float = Field(..., ge=0.0, le=1.0)
    affected_lines: List[int] = Field(default_factory=list)
    explanation: str
    attack_scenario: str
    recommendation: str
    fixed_code: str
    static_evidence: str
    original_code: str
    retrieved_knowledge: List[Dict[str, Any]] = Field(default_factory=list)

class VulnerabilityReportPayload(BaseModel):
    analysis_id: str
    contract_name: str
    timestamp: str
    total_findings: int
    is_vulnerable: bool
    severity_counts: Dict[str, int] = Field(default_factory=lambda: {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0
    })
    findings: List[VerifiedVulnerability] = Field(default_factory=list)
    summary: str
