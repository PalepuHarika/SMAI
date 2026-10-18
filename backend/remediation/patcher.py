"""
Source-aware patch system for Solidity vulnerability remediation.
Applies deterministic, non-overlapping patches to fix multiple findings.
"""
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class SourcePatch:
    """Represents a single source code patch."""
    finding_id: str
    category: str
    line_start: int
    line_end: int
    original_lines: List[str]
    patched_lines: List[str]
    description: str
    manual_required: bool = False
    manual_reason: Optional[str] = None


class SourcePatcher:
    """
    Applies source-aware patches to Solidity code.
    Ensures patches don't overlap and are applied in a deterministic order.
    """
    
    def __init__(self, source_code: str):
        self.original_lines = source_code.splitlines()
        self.current_lines = list(self.original_lines)
        self.patches: List[SourcePatch] = []
        self.line_offset = 0  # Tracks line number shifts from applied patches
    
    def add_patch(self, patch: SourcePatch) -> bool:
        """
        Add a patch if it doesn't conflict with existing patches.
        Returns True if patch was added, False if it conflicts.
        """
        # Check for overlap with existing patches
        patch_start = patch.line_start + self.line_offset
        patch_end = patch.line_end + self.line_offset
        
        for existing in self.patches:
            ex_start = existing.line_start + self.line_offset
            ex_end = existing.line_end + self.line_offset
            
            # Check for overlap
            if not (patch_end < ex_start or patch_start > ex_end):
                return False  # Overlap detected
        
        # Apply the patch
        self._apply_patch(patch)
        self.patches.append(patch)
        return True
    
    def _apply_patch(self, patch: SourcePatch):
        """Apply a single patch to the current code."""
        start_idx = patch.line_start + self.line_offset - 1
        end_idx = patch.line_end + self.line_offset
        
        # Replace the lines
        self.current_lines[start_idx:end_idx] = patch.patched_lines
        
        # Update line offset for subsequent patches
        line_delta = len(patch.patched_lines) - len(patch.original_lines)
        self.line_offset += line_delta
    
    def get_patched_code(self) -> str:
        """Get the current patched code."""
        return "\n".join(self.current_lines)
    
    def get_original_code(self) -> str:
        """Get the original code."""
        return "\n".join(self.original_lines)
    
    def get_applied_patches(self) -> List[SourcePatch]:
        """Get all applied patches."""
        return self.patches


def generate_reentrancy_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate a source-aware patch for reentrancy vulnerability.
    Only applies CEI pattern for recognized withdrawal patterns.
    """
    if finding.get("category") != "reentrancy":
        return None
    
    lines = source_code.splitlines()
    line_start = finding.get("line_start", 1)
    line_end = finding.get("line_end", line_start)
    function_name = finding.get("function", "")
    
    if not function_name:
        return None
    
    # Extract the function code
    func_lines = lines[line_start - 1:line_end]
    
    # Look for the classic reentrancy pattern: external call before state update
    pattern = re.compile(
        r'balances\[msg\.sender\]\s*[-=]\s*.*?\n.*?msg\.sender\.call',
        re.MULTILINE | re.DOTALL
    )
    
    func_code = "\n".join(func_lines)
    match = pattern.search(func_code)
    
    if not match:
        return None
    
    # Apply CEI pattern: move state update before external call
    original_snippet = match.group(0)
    
    # Extract the balance subtraction and external call
    balance_sub = re.search(r'balances\[msg\.sender\]\s*[-=]\s*([^;]+);', original_snippet)
    external_call = re.search(r'\(bool\s+\w+,\s*\)\s*=\s*msg\.sender\.call\s*{[^}]+\}\s*\([^)]*\);', original_snippet)
    
    if not balance_sub or not external_call:
        return None
    
    # Reconstruct with CEI pattern
    balance_stmt = balance_sub.group(0)
    call_stmt = external_call.group(0)
    
    patched_snippet = f"{balance_stmt}\n            {call_stmt}"
    
    # Preserve indentation
    indent_match = re.match(r'^(\s*)', original_snippet)
    if indent_match:
        indent = indent_match.group(1)
        patched_snippet = "\n".join(indent + line for line in patched_snippet.split("\n"))
    
    patched_lines = patched_snippet.split("\n")
    original_lines = original_snippet.split("\n")
    
    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="reentrancy",
        line_start=line_start,
        line_end=line_end,
        original_lines=original_lines,
        patched_lines=patched_lines,
        description="Applied Checks-Effects-Interactions pattern",
        manual_required=False
    )


def generate_floating_pragma_patch(source_code: str, finding: Dict[str, Any]) -> Optional[SourcePatch]:
    """
    Generate a source-aware patch for floating pragma.
    Uses the existing generate_floating_pragma_fix but converts to patch format.
    """
    if finding.get("category") != "floating-pragma":
        return None
    
    from backend.llm.reasoner import generate_floating_pragma_fix
    
    fix_result = generate_floating_pragma_fix(source_code)
    fixed_code = fix_result.get("fixed_code", "")
    
    if not fixed_code or fixed_code == source_code:
        return None
    
    # Convert to patch by finding diff
    original_lines = source_code.splitlines()
    fixed_lines = fixed_code.splitlines()
    
    # Find which lines changed
    diff_start = 0
    for i, (orig, fixed) in enumerate(zip(original_lines, fixed_lines)):
        if orig != fixed:
            diff_start = i
            break
    
    # Find end of diff
    diff_end = len(original_lines)
    for i in range(len(original_lines) - 1, -1, -1):
        if original_lines[i] != fixed_lines[i]:
            diff_end = i + 1
            break
    
    if diff_start >= diff_end:
        return None
    
    return SourcePatch(
        finding_id=finding.get("finding_id", ""),
        category="floating-pragma",
        line_start=diff_start + 1,
        line_end=diff_end,
        original_lines=original_lines[diff_start:diff_end],
        patched_lines=fixed_lines[diff_start:diff_end],
        description="Pinned floating pragma to exact version",
        manual_required=False
    )


def apply_finding_patches(source_code: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Apply compatible patches for all findings.
    Returns dict with:
    - corrected_code: str
    - applied_patches: List[SourcePatch]
    - skipped_findings: List of finding IDs that couldn't be patched
    - compilation_result: Dict from compiler validation
    """
    patcher = SourcePatcher(source_code)
    skipped = []
    
    for finding in findings:
        # Try different patch generators based on category
        patch = None
        
        if finding.get("category") == "reentrancy":
            patch = generate_reentrancy_patch(source_code, finding)
        elif finding.get("category") == "floating-pragma":
            patch = generate_floating_pragma_patch(source_code, finding)
        
        if patch:
            if patcher.add_patch(patch):
                continue
            else:
                # Patch conflicted with an existing patch
                skipped.append(finding.get("finding_id", ""))
        else:
            # No patch available for this category
            skipped.append(finding.get("finding_id", ""))
    
    # Validate the corrected code
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    
    corrected_code = patcher.get_patched_code()
    syntax_result = analyzer.validate_syntax(corrected_code)
    
    # Re-analyze to check if vulnerabilities were resolved
    original_findings = analyzer.analyze(source_code)
    corrected_findings = analyzer.analyze(corrected_code)
    
    return {
        "corrected_code": corrected_code,
        "applied_patches": patcher.get_applied_patches(),
        "skipped_findings": skipped,
        "syntax_validation": syntax_result,
        "original_findings_count": len(original_findings),
        "corrected_findings_count": len(corrected_findings),
        "resolved_categories": [
            f.category for f in original_findings
            if f.category not in [cf.category for cf in corrected_findings]
        ]
    }
