"""
Source-aware patch system and complete corrected contract generation for Solidity.
Applies deterministic, non-overlapping patches to fix multiple vulnerabilities,
preserves unaffected code and business logic, and performs honest multi-stage verification.
"""
import re
import copy
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SourcePatch:
    """Represents a single source-aware code patch."""
    finding_id: str
    category: str
    line_start: int
    line_end: int
    original_lines: List[str]
    patched_lines: List[str]
    description: str
    patch_applied: bool = True
    manual_required: bool = False
    manual_reason: Optional[str] = None
    verification_status: str = "FIX SUGGESTED"  # FIX SUGGESTED | FIX VERIFIED | MANUAL REVIEW REQUIRED | VERIFICATION FAILED
    verification_reason: Optional[str] = None
    compiler_verification: str = "not_performed"  # verified | failed | not_performed


class SourcePatcher:
    """
    Applies non-overlapping source patches from bottom-to-top or incrementally to preserve line indexing.
    """
    def __init__(self, source_code: str):
        self.original_source = source_code
        self.original_lines = source_code.splitlines()
        self.current_lines = list(self.original_lines)
        self.line_offset = 0
        self.patches: List[SourcePatch] = []
        self.applied_patches: List[SourcePatch] = []
        self.skipped_patches: List[SourcePatch] = []

    def add_patch(self, patch: SourcePatch) -> bool:
        """
        Add and apply a single patch if it does not overlap with existing patches.
        Returns True if applied, False if rejected due to overlap or invalid range.
        """
        if patch.manual_required:
            patch.patch_applied = False
            self.skipped_patches.append(patch)
            return False

        # Validate bounds
        if patch.line_start < 1 or patch.line_end > len(self.original_lines) or patch.line_start > patch.line_end:
            patch.patch_applied = False
            self.skipped_patches.append(patch)
            return False

        # Check for overlap against existing patches (in original line coordinates)
        for existing in self.patches:
            if max(patch.line_start, existing.line_start) <= min(patch.line_end, existing.line_end):
                patch.patch_applied = False
                self.skipped_patches.append(patch)
                return False

        # Re-apply all patches deterministically in descending line order
        self.patches.append(patch)
        self._rebuild_current_lines()
        patch.patch_applied = True
        if patch not in self.applied_patches:
            self.applied_patches.append(patch)
        return True

    def _rebuild_current_lines(self):
        """Rebuilds current_lines from original_lines applying all patches in reverse line order."""
        working = list(self.original_lines)
        sorted_patches = sorted(self.patches, key=lambda x: x.line_start, reverse=True)
        for p in sorted_patches:
            s_idx = p.line_start - 1
            e_idx = p.line_end
            working[s_idx:e_idx] = p.patched_lines
        self.current_lines = working
        self.line_offset = len(self.current_lines) - len(self.original_lines)

    def get_patched_code(self) -> str:
        """Get the current patched source code."""
        return "\n".join(self.current_lines)

    def get_original_code(self) -> str:
        """Get the original source code."""
        return self.original_source

    def get_applied_patches(self) -> List[SourcePatch]:
        """Get all applied patches."""
        return self.applied_patches

    def apply_patches(self, candidate_patches: List[SourcePatch]) -> Tuple[str, List[SourcePatch], List[SourcePatch]]:
        """
        Apply compatible, non-overlapping candidate patches.
        Patches are sorted by line_start in descending order (bottom-to-top)
        so that line coordinate offsets do not invalidate preceding line ranges.
        """
        for p in candidate_patches:
            self.add_patch(p)

        corrected_code = self.get_patched_code()
        return corrected_code, self.applied_patches, self.skipped_patches


# ─────────────────────────────────────────────────────────────────────────────
# Specific Patch Generators
# ─────────────────────────────────────────────────────────────────────────────

def generate_reentrancy_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate CEI (Checks-Effects-Interactions) patch for recognized reentrancy pattern.
    Reorders state update before external call while preserving checks and return status.
    
    Note: This function only generates a manual-review patch. Automatic CEI reordering
    is not supported because it may alter business logic, break state dependencies,
    or introduce subtle bugs. Reentrancy should be fixed manually or using a ReentrancyGuard.
    """
    category = finding.get("category", "")
    if "reentrancy" not in category.lower():
        return None

    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)

    # Reentrancy requires manual remediation to ensure business logic is preserved
    snippet_lines = lines[max(0, line_start - 1):min(len(lines), line_end)]
    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="reentrancy",
        line_start=line_start,
        line_end=line_end,
        original_lines=snippet_lines if snippet_lines else [lines[line_start - 1]] if line_start <= len(lines) else [],
        patched_lines=[],
        description="Manual remediation required for reentrancy vulnerability.",
        manual_required=True,
        manual_reason="Reentrancy vulnerabilities require manual architectural review. Use ReentrancyGuard mutex or carefully apply Checks-Effects-Interactions pattern while preserving business logic and state dependencies.",
        verification_status="MANUAL REVIEW REQUIRED",
        verification_reason="Automatic CEI reordering is not supported to avoid altering business logic or introducing subtle bugs."
    )


def generate_tx_origin_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate patch for tx.origin authorization misuse (SWC-115).
    Replaces tx.origin with msg.sender in authorization checks.
    """
    category = finding.get("category", "")
    if "tx-origin" not in category.lower() and "tx.origin" not in category.lower():
        return None

    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)

    # Search for tx.origin line
    target_line_idx = -1
    for idx in range(max(0, line_start - 2), min(len(lines), line_end + 2)):
        if "tx.origin" in lines[idx]:
            target_line_idx = idx
            break

    if target_line_idx == -1:
        return None

    orig_line = lines[target_line_idx]
    clean = re.sub(r'//.*$', '', orig_line).strip()

    # If used only in event emission, not an authorization vulnerability
    if clean.startswith("emit ") or "emit UserAction" in clean:
        return None

    patched_line = orig_line.replace("tx.origin", "msg.sender")

    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="tx-origin",
        line_start=target_line_idx + 1,
        line_end=target_line_idx + 1,
        original_lines=[orig_line],
        patched_lines=[patched_line],
        description="Replaced tx.origin with msg.sender to enforce direct caller authorization (SWC-115).",
        verification_status="FIX SUGGESTED",
        verification_reason="tx.origin replaced with msg.sender. Manual review required to ensure authorization logic is correct."
    )


def generate_unchecked_call_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate patch for unchecked external calls (SWC-104).
    Adds return value checking to low-level calls.
    """
    category = finding.get("category", "")
    if "unchecked-call" not in category.lower():
        return None

    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)

    # Search for call line
    target_line_idx = -1
    call_line = ""
    for idx in range(max(0, line_start - 1), min(len(lines), line_end)):
        line = lines[idx]
        clean = re.sub(r'//.*$', '', line).strip()
        if re.search(r'\.call\{', clean) or re.search(r'\.delegatecall\{', clean) or re.search(r'\.staticcall\{', clean):
            if not re.search(r'\(\s*(bool|success)\s*\w', clean):  # Not already checked
                target_line_idx = idx
                call_line = line
                break

    if target_line_idx == -1:
        return None

    # Add require check after the call
    indent_match = re.match(r'^(\s*)', call_line)
    indent = indent_match.group(1) if indent_match else "        "

    patched_lines = [call_line, f"{indent}require(success, \"Low-level call failed\");"]

    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="unchecked-call",
        line_start=target_line_idx + 1,
        line_end=target_line_idx + 1,
        original_lines=[call_line],
        patched_lines=patched_lines,
        description="Added require check for low-level call return value (SWC-104).",
        verification_status="FIX SUGGESTED",
        verification_reason="Return value check added. Manual review and testing required."
    )


def generate_missing_access_control_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate patch for missing access control (SWC-105).
    WARNING: Cannot safely infer intended access policy. Always requires manual review.
    """
    category = finding.get("category", "")
    if "missing-access-control" not in category.lower():
        return None

    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)

    # Extract function header
    func_line_idx = -1
    for idx in range(max(0, line_start - 1), min(len(lines), line_end)):
        if "function" in lines[idx]:
            func_line_idx = idx
            break

    if func_line_idx == -1:
        return None

    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="missing-access-control",
        line_start=func_line_idx + 1,
        line_end=func_line_idx + 1,
        original_lines=[lines[func_line_idx]],
        patched_lines=[],
        description="Manual remediation required for missing access control (SWC-105).",
        manual_required=True,
        manual_reason="Access control policy cannot be inferred automatically. Manual review required to add appropriate modifiers (e.g., onlyOwner, onlyAdmin) or implement intended authorization logic.",
        verification_status="MANUAL REVIEW REQUIRED",
        verification_reason="Access control policy requires manual specification."
    )


def generate_unprotected_selfdestruct_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate patch for unprotected selfdestruct (SWC-106).
    Adds onlyOwner modifier if contract has an owner variable.
    """
    category = finding.get("category", "")
    if "unprotected-selfdestruct" not in category.lower():
        return None

    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)

    # Check if contract has an owner variable
    has_owner = any("address public owner" in line or "address owner" in line for line in lines)

    func_line_idx = -1
    for idx in range(max(0, line_start - 1), min(len(lines), line_end)):
        if "function" in lines[idx]:
            func_line_idx = idx
            break

    if func_line_idx == -1:
        return None

    if has_owner:
        func_line = lines[func_line_idx]
        patched_line = func_line.replace(" external", " onlyOwner external")

        return SourcePatch(
            finding_id=finding.get("finding_id", ""),
            category="unprotected-selfdestruct",
            line_start=func_line_idx + 1,
            line_end=func_line_idx + 1,
            original_lines=[func_line],
            patched_lines=[patched_line],
            description="Added onlyOwner modifier to selfdestruct function (SWC-106).",
            verification_status="FIX SUGGESTED",
            verification_reason="onlyOwner modifier added. Manual review and testing required."
        )
    else:
        return SourcePatch(
            finding_id=finding.get("finding_id", ""),
            category="unprotected-selfdestruct",
            line_start=func_line_idx + 1,
            line_end=func_line_idx + 1,
            original_lines=[lines[func_line_idx]],
            patched_lines=[],
            description="Manual remediation required for unprotected selfdestruct (SWC-106).",
            manual_required=True,
            manual_reason="No owner variable found. Manual review required to implement appropriate authorization for selfdestruct.",
            verification_status="MANUAL REVIEW REQUIRED",
            verification_reason="No owner variable; manual authorization required."
        )


def generate_timestamp_dependence_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate patch for timestamp dependence (SWC-116/120).
    WARNING: No safe automatic fix - requires architectural change to use randomness oracle.
    """
    category = finding.get("category", "")
    if "timestamp-dependence" not in category.lower():
        return None

    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)

    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="timestamp-dependence",
        line_start=line_start,
        line_end=line_end,
        original_lines=lines[max(0, line_start - 1):min(len(lines), line_end)],
        patched_lines=[],
        description="Manual remediation required for timestamp dependence (SWC-116/120).",
        manual_required=True,
        manual_reason="Timestamp-based randomness is not fixable with a simple code change. Requires integration with a randomness oracle (e.g., Chainlink VRF) or architectural redesign.",
        verification_status="MANUAL REVIEW REQUIRED",
        verification_reason="Timestamp dependence requires architectural redesign with randomness oracle."
    )


def generate_floating_pragma_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate patch for floating pragma (SWC-103).
    Pins pragma to exact compiler version 0.8.20.
    """
    category = finding.get("category", "")
    if "floating-pragma" not in category.lower() and "pragma" not in category.lower():
        return None

    lines = source_code.splitlines()
    target_idx = -1

    for idx, line in enumerate(lines):
        clean = line.strip()
        if clean.startswith("pragma solidity"):
            target_idx = idx
            break

    if target_idx == -1:
        return None

    orig_line = lines[target_idx]
    # Pin to exact 0.8.20 (or 0.8.0 if pragma was 0.8.0)
    pinned_version = "0.8.20"
    if "0.8.0" in orig_line:
        pinned_version = "0.8.0"
    patched_line = f"pragma solidity {pinned_version};"

    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="floating-pragma",
        line_start=target_idx + 1,
        line_end=target_idx + 1,
        original_lines=[orig_line],
        patched_lines=[patched_line],
        description=f"Pinned floating pragma to exact compiler version {pinned_version} (SWC-103).",
        verification_status="FIX SUGGESTED",
        verification_reason=f"Pragma pinned to {pinned_version}. Manual review and testing required."
    )


def generate_missing_zero_check_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate patch for missing zero address validation (SWC-136).
    Inserts require check before address assignment.
    """
    category = finding.get("category", "")
    if "missing-zero-check" not in category.lower() and "zero-check" not in category.lower():
        return None

    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)

    target_idx = min(len(lines) - 1, max(0, line_start - 1))
    orig_line = lines[target_idx]

    # Look for assignment: lhs = rhs;
    match = re.search(r'([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_]+)\s*;', orig_line)
    if not match:
        return None

    param = match.group(2)
    indent_match = re.match(r'^(\s*)', orig_line)
    indent = indent_match.group(1) if indent_match else "        "

    patched_lines = [
        f"{indent}require({param} != address(0), \"Zero address not allowed\");",
        orig_line
    ]

    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="missing-zero-check",
        line_start=target_idx + 1,
        line_end=target_idx + 1,
        original_lines=[orig_line],
        patched_lines=patched_lines,
        description=f"Added zero-address check for parameter '{param}' before assignment (SWC-136).",
        verification_status="FIX SUGGESTED",
        verification_reason=f"Zero-address check added for {param}. Manual review and testing required."
    )


def generate_manual_review_patch(source_code: str, finding: Dict[str, Any]) -> SourcePatch:
    """
    Generates a formal manual-review finding for vulnerabilities where automatic
    remediation cannot safely invent authorization rules or change business logic.
    """
    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)
    category = finding.get("category", "")

    snippet_lines = lines[max(0, line_start - 1):min(len(lines), line_end)]
    if not snippet_lines and line_start <= len(lines):
        snippet_lines = [lines[line_start - 1]]

    reason_map = {
        "missing-access-control": "Access control policies (e.g. onlyOwner or AccessControl role) must be defined according to specification. Automatic authorization cannot be safely invented without altering intended business logic.",
        "unprotected-selfdestruct": "Contract destruction requires authorized access control (e.g. onlyOwner or multi-sig). Automatic authorization cannot be safely invented without specification.",
        "dangerous-delegatecall": "Target contract must be verified as trusted and immutable. Upgradability architecture must be defined manually.",
        "uninitialized-storage": "Storage layout requires explicit memory or storage pointer designation based on intended state persistence."
    }

    reason = reason_map.get(category, f"Automatic remediation is unavailable for {category}. Manual security review is required.")

    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category=category,
        line_start=line_start,
        line_end=line_end,
        original_lines=snippet_lines,
        patched_lines=[],
        description="Manual remediation required.",
        manual_required=True,
        manual_reason=reason,
        verification_status="MANUAL REVIEW REQUIRED",
        verification_reason=reason
    )


def create_patch_for_finding(source_code: str, finding: Dict[str, Any]) -> SourcePatch:
    """Dispatches finding to appropriate patch generator or manual review."""
    cat = finding.get("category", "").lower()

    if "reentrancy" in cat:
        patch = generate_reentrancy_patch(source_code, finding)
        if patch:
            return patch

    elif "tx-origin" in cat or "tx.origin" in cat:
        patch = generate_tx_origin_patch(source_code, finding)
        if patch:
            return patch

    elif "floating-pragma" in cat or "pragma" in cat:
        patch = generate_floating_pragma_patch(source_code, finding)
        if patch:
            return patch

    elif "unchecked-call" in cat:
        patch = generate_unchecked_call_patch(source_code, finding)
        if patch:
            return patch

    elif "missing-access-control" in cat:
        patch = generate_missing_access_control_patch(source_code, finding)
        if patch:
            return patch

    elif "unprotected-selfdestruct" in cat:
        patch = generate_unprotected_selfdestruct_patch(source_code, finding)
        if patch:
            return patch

    elif "timestamp-dependence" in cat:
        patch = generate_timestamp_dependence_patch(source_code, finding)
        if patch:
            return patch

    elif "missing-zero-check" in cat or "zero-check" in cat:
        patch = generate_missing_zero_check_patch(source_code, finding)
        if patch:
            return patch

    return generate_manual_review_patch(source_code, finding)


# ─────────────────────────────────────────────────────────────────────────────
# Combined Contract Generator & Multi-Stage Fix Verification
# ─────────────────────────────────────────────────────────────────────────────

def remediate_contract(
    source_code: str,
    findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Generate the complete corrected contract and perform honest multi-stage verification.
    Returns:
    - corrected_code: str
    - applied_patches: List[SourcePatch]
    - skipped_patches: List[SourcePatch]
    - patches_by_finding_id: Dict[str, SourcePatch]
    - syntax_valid: bool
    - compiler_verification: str ('verified' | 'failed' | 'not_performed')
    - resolved_categories: List[str]
    - remaining_findings_count: int
    - original_findings_count: int
    - summary: Dict[str, Any]
    """
    candidate_patches: List[SourcePatch] = []
    patches_by_id: Dict[str, SourcePatch] = {}

    for f in findings:
        patch = create_patch_for_finding(source_code, f)
        candidate_patches.append(patch)
        fid = f.get("finding_id") or f.get("id", "")
        if fid:
            patches_by_id[fid] = patch

    patcher = SourcePatcher(source_code)
    corrected_code, applied_patches, skipped_patches = patcher.apply_patches(candidate_patches)

    # 1. Syntax & Compiler Validation
    try:
        from backend.compiler.solc_validator import validate_solidity_source
        syntax_result = validate_solidity_source(corrected_code)
        syntax_valid = syntax_result.get("is_valid", False)
        compiler_available = syntax_result.get("compiler_available", False)

        if compiler_available:
            compiler_status = "verified" if syntax_valid else "failed"
        else:
            compiler_status = "not_performed"
    except ImportError:
        # Fallback to static analyzer's validate_syntax
        from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
        analyzer = SolidityStaticAnalyzer()
        syntax_result = analyzer.validate_syntax(corrected_code)
        syntax_valid = syntax_result.get("is_valid", False)
        compiler_available = syntax_result.get("compiler_available", False)
        compiler_status = "not_performed"

    # 2. Re-analysis of corrected code using static analyzer
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    original_static = analyzer.analyze(source_code)
    corrected_static = analyzer.analyze(corrected_code)

    orig_categories = {f.category for f in original_static}
    corr_categories = {f.category for f in corrected_static}
    resolved_categories = sorted(list(orig_categories - corr_categories))

    # Check for newly introduced severe findings
    new_severe = [
        f for f in corrected_static
        if f.severity in ["Critical", "High"] and f.category not in orig_categories
    ]
    has_new_severe = len(new_severe) > 0

    # 3. Assign honest verification status to each applied patch
    for patch in applied_patches:
        patch.compiler_verification = compiler_status
        is_cat_resolved = (patch.category in resolved_categories) or (patch.category not in corr_categories)

        if not syntax_valid:
            patch.verification_status = "VERIFICATION FAILED"
            patch.verification_reason = "Syntax validation failed on the generated contract."
        elif has_new_severe:
            patch.verification_status = "VERIFICATION FAILED"
            patch.verification_reason = f"New {new_severe[0].severity} vulnerability ({new_severe[0].category}) was introduced."
        elif not is_cat_resolved:
            patch.verification_status = "VERIFICATION FAILED"
            patch.verification_reason = f"Target vulnerability ({patch.category}) is still detected in corrected contract."
        else:
            if compiler_status == "verified":
                patch.verification_status = "FIX VERIFIED"
                patch.verification_reason = "Syntax valid, compiler verified (solc), target vulnerability eliminated with 0 new severe findings."
            elif compiler_status == "not_performed":
                patch.verification_status = "FIX SUGGESTED"
                patch.verification_reason = "Syntax valid and target eliminated in re-analysis. Compiler verification unavailable (solc compiler not installed locally)."
            else:
                patch.verification_status = "VERIFICATION FAILED"
                patch.verification_reason = "Compiler verification failed on the corrected code."

    summary = {
        "applied_patches_count": len(applied_patches),
        "skipped_findings_count": len(skipped_patches),
        "resolved_categories": resolved_categories,
        "syntax_valid": syntax_valid,
        "compiler_verification": compiler_status,
        "original_findings": len(original_static),
        "corrected_findings": len(corrected_static)
    }

    return {
        "corrected_code": corrected_code,
        "applied_patches": applied_patches,
        "skipped_patches": skipped_patches,
        "patches_by_finding_id": patches_by_id,
        "syntax_valid": syntax_valid,
        "compiler_verification": compiler_status,
        "resolved_categories": resolved_categories,
        "remaining_findings_count": len(corrected_static),
        "original_findings_count": len(original_static),
        "summary": summary
    }


def apply_finding_patches(source_code: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compatibility wrapper for pipeline integration."""
    result = remediate_contract(source_code, findings)
    return {
        "corrected_code": result["corrected_code"],
        "applied_patches": result["applied_patches"],
        "skipped_findings": [p.finding_id for p in result["skipped_patches"]],
        "syntax_validation": {
            "is_valid": result["syntax_valid"],
            "errors": [] if result["syntax_valid"] else [{"line": 1, "column": 1, "message": "Syntax validation failed"}],
            "compiler_available": result["compiler_verification"] != "not_performed",
            "compiler_verification": result["compiler_verification"]
        },
        "original_findings_count": result["original_findings_count"],
        "corrected_findings_count": result["remaining_findings_count"],
        "resolved_categories": result["resolved_categories"],
        "patches_by_id": result["patches_by_finding_id"]
    }
