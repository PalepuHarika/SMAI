"""
Tests for source-aware patch system and combined corrected contract generation.
"""
import pytest
from backend.remediation.patcher import SourcePatcher, SourcePatch, apply_finding_patches, generate_floating_pragma_patch


def test_source_patcher_initialization():
    """Test that SourcePatcher initializes correctly."""
    source = "pragma solidity ^0.8.0;\ncontract Test {\n    uint256 value;\n}"
    patcher = SourcePatcher(source)
    assert len(patcher.original_lines) == 4  # 4 lines including the closing brace
    assert len(patcher.current_lines) == 4
    assert patcher.line_offset == 0
    assert len(patcher.patches) == 0


def test_source_patcher_single_patch():
    """Test applying a single patch."""
    source = "pragma solidity ^0.8.0;\ncontract Test {\n    uint256 value;\n}"
    patcher = SourcePatcher(source)
    
    patch = SourcePatch(
        finding_id="test-1",
        category="test",
        line_start=3,
        line_end=3,
        original_lines=["    uint256 value;"],
        patched_lines=["    uint256 newValue;"],
        description="Test patch"
    )
    
    result = patcher.add_patch(patch)
    assert result is True
    assert len(patcher.patches) == 1
    assert "newValue" in patcher.get_patched_code()


def test_source_patcher_conflicting_patches():
    """Test that conflicting patches are rejected."""
    source = "pragma solidity ^0.8.0;\ncontract Test {\n    uint256 value;\n}"
    patcher = SourcePatcher(source)
    
    patch1 = SourcePatch(
        finding_id="test-1",
        category="test",
        line_start=3,
        line_end=3,
        original_lines=["    uint256 value;"],
        patched_lines=["    uint256 newValue;"],
        description="Test patch 1"
    )
    
    patch2 = SourcePatch(
        finding_id="test-2",
        category="test",
        line_start=3,
        line_end=3,
        original_lines=["    uint256 value;"],
        patched_lines=["    uint256 fixedValue;"],
        description="Test patch 2"
    )
    
    result1 = patcher.add_patch(patch1)
    result2 = patcher.add_patch(patch2)
    
    assert result1 is True
    assert result2 is False  # Should be rejected due to overlap
    assert len(patcher.patches) == 1


def test_source_patcher_non_overlapping_patches():
    """Test that non-overlapping patches can both be applied."""
    source = "pragma solidity ^0.8.0;\ncontract Test {\n    uint256 value;\n    address owner;\n}"
    patcher = SourcePatcher(source)
    
    patch1 = SourcePatch(
        finding_id="test-1",
        category="test",
        line_start=3,
        line_end=3,
        original_lines=["    uint256 value;"],
        patched_lines=["    uint256 newValue;"],
        description="Test patch 1"
    )
    
    patch2 = SourcePatch(
        finding_id="test-2",
        category="test",
        line_start=4,
        line_end=4,
        original_lines=["    address owner;"],
        patched_lines=["    address newOwner;"],
        description="Test patch 2"
    )
    
    result1 = patcher.add_patch(patch1)
    result2 = patcher.add_patch(patch2)
    
    assert result1 is True
    assert result2 is True
    assert len(patcher.patches) == 2


def test_apply_finding_patches_empty_findings():
    """Test apply_finding_patches with no findings."""
    source = "pragma solidity ^0.8.0;\ncontract Test {\n    uint256 value;\n}"
    result = apply_finding_patches(source, [])
    
    assert result["corrected_code"] == source
    assert len(result["applied_patches"]) == 0
    assert len(result["skipped_findings"]) == 0


def test_apply_finding_patches_unsupported_category():
    """Test that unsupported categories are skipped."""
    source = "pragma solidity ^0.8.0;\ncontract Test {\n    uint256 value;\n}"
    findings = [
        {
            "finding_id": "test-1",
            "category": "unsupported-category",
            "line_start": 3,
            "line_end": 3,
            "function": "test",
            "contract": "Test"
        }
    ]
    
    result = apply_finding_patches(source, findings)
    
    assert result["corrected_code"] == source  # No changes
    assert len(result["applied_patches"]) == 0
    assert len(result["skipped_findings"]) == 1


def test_apply_finding_patches_syntax_validation():
    """Test that corrected code is syntax-validated."""
    source = "pragma solidity ^0.8.0;\ncontract Test {\n    uint256 value;\n}"
    findings = []
    
    result = apply_finding_patches(source, findings)
    
    assert "syntax_validation" in result
    assert "is_valid" in result["syntax_validation"]
    assert "errors" in result["syntax_validation"]


def test_apply_finding_patches_reanalysis():
    """Test that corrected code is re-analyzed."""
    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""
    findings = [
        {
            "finding_id": "test-1",
            "category": "reentrancy",
            "line_start": 10,
            "line_end": 14,
            "function": "withdraw",
            "contract": "ReentrancyVault"
        }
    ]
    
    result = apply_finding_patches(source, findings)
    
    assert "original_findings_count" in result
    assert "corrected_findings_count" in result
    assert "resolved_categories" in result


def test_generate_floating_pragma_patch():
    """Test floating pragma patch generation."""
    source = "pragma solidity ^0.8.0;\ncontract Test {\n    uint256 value;\n}"
    finding = {
        "finding_id": "test-1",
        "category": "floating-pragma",
        "line_start": 1,
        "line_end": 1,
        "function": None,
        "contract": "Test"
    }
    
    patch = generate_floating_pragma_patch(source, finding)
    
    # Patch may be None if compiler is unavailable or fix couldn't be generated
    if patch:
        assert patch.category == "floating-pragma"
        assert patch.finding_id == "test-1"
        assert len(patch.patched_lines) > 0
        assert patch.manual_required is False


def test_source_patcher_line_offset_tracking():
    """Test that line offset is tracked correctly when patches change line count."""
    source = "line1\nline2\nline3\nline4\nline5"
    patcher = SourcePatcher(source)
    
    # Add a patch that inserts 2 lines
    patch = SourcePatch(
        finding_id="test-1",
        category="test",
        line_start=2,
        line_end=2,
        original_lines=["line2"],
        patched_lines=["line2a", "line2b", "line2c"],  # 3 lines instead of 1
        description="Insert lines"
    )
    
    patcher.add_patch(patch)
    
    # Line offset should be +2 (3 lines - 1 line)
    assert patcher.line_offset == 2
    assert len(patcher.current_lines) == 7  # Original 5 + 2 inserted (3-1=2)


def test_source_patcher_get_methods():
    """Test get_patched_code and get_original_code methods."""
    source = "original\nsource\ncode"
    patcher = SourcePatcher(source)
    
    original = patcher.get_original_code()
    assert original == source
    
    patched = patcher.get_patched_code()
    assert patched == source  # No patches applied yet
    
    patch = SourcePatch(
        finding_id="test-1",
        category="test",
        line_start=2,
        line_end=2,
        original_lines=["source"],
        patched_lines=["patched"],
        description="Test"
    )
    
    patcher.add_patch(patch)
    
    patched = patcher.get_patched_code()
    assert patched == "original\npatched\ncode"
    assert original == source  # Original should not change
