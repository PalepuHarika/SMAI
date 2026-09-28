import pytest
import hashlib
from backend.core.integrity import (
    hash_source_sha256,
    hash_source_keccak256,
    canonical_json_dumps,
    canonicalize_finding,
    compute_finding_hash,
    compute_findings_hash,
    compute_findings_merkle_root,
    compute_report_hash,
    extract_solidity_pragma,
    get_git_commit,
    ANALYZER_VERSION
)
from backend.core.finding import VerifiedVulnerability

def test_source_hashing_same_and_different():
    src1 = "pragma solidity ^0.8.0;\ncontract Vault { uint public balance; }"
    src2 = "pragma solidity ^0.8.0;\ncontract Vault { uint public balance; }"
    src3 = "pragma solidity ^0.8.0;\ncontract Vault { uint public bal; }"

    h1 = hash_source_sha256(src1)
    h2 = hash_source_sha256(src2)
    h3 = hash_source_sha256(src3)

    # Same source -> same source_hash
    assert h1 == h2
    assert len(h1) == 64
    # Different source -> different source_hash
    assert h1 != h3

def test_source_hashing_empty_and_none():
    empty_sha = hashlib.sha256(b"").hexdigest()
    assert hash_source_sha256("") == empty_sha
    assert hash_source_sha256(None) == empty_sha
    assert hash_source_sha256(b"") == empty_sha

    keccak_empty = hash_source_keccak256("")
    if keccak_empty is not None:
        # Standard Ethereum Keccak-256 of empty bytes
        assert keccak_empty == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

def test_source_hashing_unicode():
    unicode_solidity = """
    // SPDX-License-Identifier: MIT
    // 🚀 DeFi Vault with Café Rewards ☕ and é/è accents
    pragma solidity ^0.8.20;
    contract UnicodeVault {
        string public constant GREETING = "こんにちは世界";
    }
    """
    h_utf8 = hash_source_sha256(unicode_solidity)
    assert len(h_utf8) == 64
    # Rescanning identical Unicode string must be identical
    assert hash_source_sha256(unicode_solidity) == h_utf8

def test_findings_hash_deterministic_and_order_invariant():
    f1 = {
        "finding_id": "random-uuid-1111",
        "vulnerability": "reentrancy",
        "severity": "High",
        "confidence": 0.85,
        "affected_lines": [10, 11, 12],
        "function": "withdraw",
        "contract": "Vault",
        "swc_id": "SWC-107",
        "original_code": "msg.sender.call{value: bal}(\"\");",
        "fixed_code": "balances[msg.sender] = 0;\n(bool s,) = msg.sender.call{value: bal}(\"\");",
        "explanation": "State updated after external call.",
        "recommendation": "Use CEI pattern.",
        "verification_status": "CONFIRMED"
    }

    f2 = {
        "finding_id": "random-uuid-2222",
        "vulnerability": "tx-origin",
        "severity": "Medium",
        "confidence": 0.75,
        "affected_lines": [25],
        "function": "transferOwnership",
        "contract": "Vault",
        "swc_id": "SWC-115",
        "original_code": "require(tx.origin == owner);",
        "fixed_code": "require(msg.sender == owner);",
        "explanation": "tx.origin used for authentication.",
        "recommendation": "Use msg.sender.",
        "verification_status": "CONFIRMED"
    }

    # Same findings in different order must yield identical findings_hash
    hash_order_1 = compute_findings_hash([f1, f2])
    hash_order_2 = compute_findings_hash([f2, f1])
    assert hash_order_1 == hash_order_2
    assert len(hash_order_1) == 64

def test_random_ids_do_not_affect_finding_or_findings_hash():
    f1_a = {
        "finding_id": "uuid-first-run-987654",
        "vulnerability": "reentrancy",
        "severity": "High",
        "confidence": 0.85,
        "affected_lines": [10],
        "function": "withdraw",
        "contract": "Vault",
        "swc_id": "SWC-107",
        "original_code": "call()",
        "verification_status": "CONFIRMED"
    }

    f1_b = {
        "finding_id": "uuid-second-run-123456",  # Different random ID
        "vulnerability": "reentrancy",
        "severity": "High",
        "confidence": 0.85,
        "affected_lines": [10],
        "function": "withdraw",
        "contract": "Vault",
        "swc_id": "SWC-107",
        "original_code": "call()",
        "verification_status": "CONFIRMED"
    }

    assert compute_finding_hash(f1_a) == compute_finding_hash(f1_b)
    assert compute_findings_hash([f1_a]) == compute_findings_hash([f1_b])

def test_report_hash_determinism_and_invariance_to_ephemeral_fields():
    source_hash = hash_source_sha256("contract Test {}")
    f_hash = compute_findings_hash([])

    # Identical deterministic reports -> same report_hash
    r1 = compute_report_hash(
        source_hash=source_hash,
        findings_hash=f_hash,
        security_score=100,
        risk_level="Low Risk",
        analysis_mode="hybrid"
    )
    r2 = compute_report_hash(
        source_hash=source_hash,
        findings_hash=f_hash,
        security_score=100,
        risk_level="Low Risk",
        analysis_mode="hybrid"
    )
    assert r1 == r2
    assert len(r1) == 64

def test_changing_a_finding_changes_report_hash():
    source_hash = hash_source_sha256("contract Test {}")
    f1 = {"vulnerability": "reentrancy", "severity": "High", "affected_lines": [1]}
    f2 = {"vulnerability": "reentrancy", "severity": "Critical", "affected_lines": [1]}  # changed severity

    fh1 = compute_findings_hash([f1])
    fh2 = compute_findings_hash([f2])
    assert fh1 != fh2

    r1 = compute_report_hash(source_hash, fh1, 75, "Moderate Risk", "hybrid")
    r2 = compute_report_hash(source_hash, fh2, 75, "Moderate Risk", "hybrid")
    assert r1 != r2

def test_changing_security_score_changes_report_hash():
    source_hash = hash_source_sha256("contract Test {}")
    fh = compute_findings_hash([])

    r1 = compute_report_hash(source_hash, fh, security_score=85, risk_level="Moderate Risk", analysis_mode="hybrid")
    r2 = compute_report_hash(source_hash, fh, security_score=60, risk_level="Moderate Risk", analysis_mode="hybrid")
    assert r1 != r2

def test_changing_risk_level_changes_report_hash():
    source_hash = hash_source_sha256("contract Test {}")
    fh = compute_findings_hash([])

    r1 = compute_report_hash(source_hash, fh, security_score=70, risk_level="Moderate Risk", analysis_mode="hybrid")
    r2 = compute_report_hash(source_hash, fh, security_score=70, risk_level="High Risk", analysis_mode="hybrid")
    assert r1 != r2

def test_changing_analysis_mode_changes_report_hash():
    source_hash = hash_source_sha256("contract Test {}")
    fh = compute_findings_hash([])

    r_rag = compute_report_hash(source_hash, fh, security_score=100, risk_level="Low Risk", analysis_mode="rag")
    r_ai = compute_report_hash(source_hash, fh, security_score=100, risk_level="Low Risk", analysis_mode="ai")
    r_hybrid = compute_report_hash(source_hash, fh, security_score=100, risk_level="Low Risk", analysis_mode="hybrid")

    assert r_rag != r_ai
    assert r_ai != r_hybrid
    assert r_rag != r_hybrid

    # Aliases normalize to canonical modes
    assert compute_report_hash(source_hash, fh, 100, "Low Risk", "A") == r_rag
    assert compute_report_hash(source_hash, fh, 100, "Low Risk", "B") == r_ai
    assert compute_report_hash(source_hash, fh, 100, "Low Risk", "C") == r_hybrid

def test_merkle_root_computation():
    f1 = {"vulnerability": "reentrancy", "severity": "High", "affected_lines": [5]}
    f2 = {"vulnerability": "tx-origin", "severity": "Medium", "affected_lines": [12]}
    f3 = {"vulnerability": "unchecked-call", "severity": "Low", "affected_lines": [20]}

    root_empty = compute_findings_merkle_root([])
    assert len(root_empty) == 64

    root1 = compute_findings_merkle_root([f1, f2, f3])
    root2 = compute_findings_merkle_root([f3, f1, f2])  # Order invariant
    assert root1 == root2
    assert len(root1) == 64

def test_solidity_pragma_extraction():
    sol1 = "pragma solidity ^0.8.20;\ncontract A {}"
    sol2 = "pragma solidity >=0.7.0 <0.9.0;\ncontract B {}"
    sol3 = "// No pragma\ncontract C {}"

    assert extract_solidity_pragma(sol1) == "^0.8.20"
    assert extract_solidity_pragma(sol2) == ">=0.7.0 <0.9.0"
    assert extract_solidity_pragma(sol3) is None

@pytest.mark.asyncio
async def test_pipeline_integration_produces_identical_hashes():
    from backend.pipeline import SecurityPipeline
    pipeline = SecurityPipeline()
    src = """
    pragma solidity ^0.8.0;
    contract SimpleSafe {
        uint public count;
        function inc() public { count += 1; }
    }
    """

    res1 = await pipeline.scan(src, "SimpleSafe.sol", mode="rag")
    res2 = await pipeline.scan(src, "SimpleSafe.sol", mode="rag")

    # Hashes must be populated
    assert res1.source_hash is not None
    assert len(res1.source_hash) == 64
    assert res1.report_hash is not None
    assert len(res1.report_hash) == 64
    assert res1.findings_hash is not None
    assert res1.analyzer_version == ANALYZER_VERSION
    assert res1.compiler_version == "^0.8.0"

    # Both scans of identical source with same mode must yield IDENTICAL hashes
    assert res1.source_hash == res2.source_hash
    assert res1.findings_hash == res2.findings_hash
    assert res1.report_hash == res2.report_hash

    # Different contract must yield different source and report hashes
    diff_src = "pragma solidity ^0.8.0; contract Different { uint x; }"
    res_diff = await pipeline.scan(diff_src, "Different.sol", mode="rag")
    assert res_diff.source_hash != res1.source_hash
    assert res_diff.report_hash != res1.report_hash
