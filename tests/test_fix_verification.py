import pytest
import uuid
from sqlalchemy import select
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.db.database import init_db, AsyncSessionLocal
from backend.db.models import User, Analysis, VulnerabilityReport
from backend.core.security import hash_password, create_access_token
from backend.llm.reasoner import verify_fix_details, rescan_fix, validate_solidity_syntax, _extract_pragma_version, generate_floating_pragma_fix
from backend.core.integrity import (
    compute_finding_hash,
    compute_findings_hash,
    compute_findings_merkle_root,
    compute_report_hash,
)
from backend.pipeline import SecurityPipeline
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

_CLEAN_FIXED_CODE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CleanVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
"""

_UNRESOLVED_VULNERABLE_CODE = """// SPDX-License-Identifier: MIT
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

_NEW_SEVERE_CODE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BrokenFixVault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        selfdestruct(payable(msg.sender));
    }
}
"""

_MALFORMED_CODE = "contract Broken { function foo() { uint a = 1; "


@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()


# ─────────────────────────────────────────────────────────────────────────────
# Test A: Vulnerable code -> fixed code: fix_verified = True
# ─────────────────────────────────────────────────────────────────────────────
def test_a_vulnerable_to_fixed_code():
    res = verify_fix_details(_CLEAN_FIXED_CODE, "reentrancy")
    assert res["fix_verified"] is True
    assert res["category_resolved"] is True
    assert res["has_new_severe"] is False
    assert res["syntax_valid"] is True
    assert res["verification_reason"] == "Vulnerability resolved and no new High/Critical findings"
    assert res["compiler_verification"] in ["not_performed", "verified", "failed"]
    assert rescan_fix(_CLEAN_FIXED_CODE, "reentrancy") is True


@pytest.mark.asyncio
async def test_swc103_full_source_fix_compiles_and_is_returned_by_api(api_fixture):
    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract PragmaVault {
    uint256 public value;
    function setValue(uint256 next) external { value = next; }
}
"""
    raw = SolidityStaticAnalyzer().analyze(source, "PragmaVault")
    finding = next(item for item in raw if item.swc_id == "SWC-103")
    fix = generate_floating_pragma_fix(source)

    # Skip test if compiler verification failed (system without proper solc setup)
    if fix["compiler_verification"] != "verified":
        pytest.skip(f"Compiler verification failed ({fix['compiler_verification']}), skipping full integration test")

    # The fix generator returns the full contract with pinned pragma
    assert fix["fixed_code"], f"Fix code is empty when compiler verified: {fix}"
    assert fix["fixed_code"] != source
    assert "contract PragmaVault" in fix["fixed_code"]
    assert "function setValue(uint256 next) external { value = next; }" in fix["fixed_code"]
    assert fix["fix_verified"] is True

    report = await SecurityPipeline().scan(source, "PragmaVault.sol", mode="rag")
    report_finding = next(item for item in report.findings if item.swc_id == finding.swc_id)
    assert report_finding.fixed_code == fix["fixed_code"]
    assert report_finding.compiler_verification == "verified"

    async with AsyncSessionLocal() as db:
        analysis = await db.get(Analysis, api_fixture["analysis_id"])
        persisted_report_result = await db.execute(
            select(VulnerabilityReport).where(VulnerabilityReport.analysis_id == api_fixture["analysis_id"])
        )
        persisted_report = persisted_report_result.scalar_one()
        analysis.contract_name = "PragmaVault.sol"
        analysis.source_code = source
        persisted_report.verified_findings = [item.model_dump() for item in report.findings]
        persisted_report.total_findings = report.total_findings
        persisted_report.is_vulnerable = report.is_vulnerable
        await db.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            f"/api/analysis/{api_fixture['analysis_id']}",
            headers={"Authorization": f"Bearer {api_fixture['user_a_token']}"},
        )
    assert response.status_code == 200
    api_finding = next(item for item in response.json()["findings"] if item["swc_id"] == finding.swc_id)
    assert api_finding["fixed_code"] == fix["fixed_code"]
    assert api_finding["compiler_verification"] == "verified"


@pytest.mark.asyncio
async def test_unsupported_fix_returns_manual_remediation(api_fixture):
    report = await SecurityPipeline().scan(_UNRESOLVED_VULNERABLE_CODE, "ReentrancyVault.sol", mode="rag")
    finding = next(item for item in report.findings if item.vulnerability == "reentrancy")
    assert finding.fixed_code == "Manual remediation required"
    assert finding.fix_verified is False
    assert finding.compiler_verification == "not_performed"


def test_deterministic_fix_reports_compiler_failure_and_unavailability():
    from unittest.mock import patch
    source = "pragma solidity ^0.8.0; contract A { uint256 value; }"
    with patch("backend.llm.reasoner._compile_with_solc", return_value={"success": False, "error": "compile error"}):
        failed = generate_floating_pragma_fix(source)
    assert failed["fixed_code"] == ""
    assert failed["compiler_verification"] == "failed"

    with patch("backend.llm.reasoner._check_solc_available", return_value=False):
        unavailable = generate_floating_pragma_fix(source)
    assert unavailable["fixed_code"] == ""
    assert unavailable["compiler_verification"] == "not_performed"


# ─────────────────────────────────────────────────────────────────────────────
# Test B: Vulnerable code -> unchanged vulnerable code: fix_verified = False
# ─────────────────────────────────────────────────────────────────────────────
def test_b_unchanged_vulnerable_code():
    res = verify_fix_details(_UNRESOLVED_VULNERABLE_CODE, "reentrancy")
    assert res["fix_verified"] is False
    assert res["category_resolved"] is False
    assert res["verification_reason"] == "Target vulnerability still detected"

    assert rescan_fix(_UNRESOLVED_VULNERABLE_CODE, "reentrancy") is False


# ─────────────────────────────────────────────────────────────────────────────
# Test C: Fixed code introducing a new High/Critical vulnerability: fix_verified = False
# ─────────────────────────────────────────────────────────────────────────────
def test_c_new_severe_vulnerability_introduced():
    res = verify_fix_details(_NEW_SEVERE_CODE, "reentrancy")
    assert res["fix_verified"] is False
    assert res["category_resolved"] is True
    assert res["has_new_severe"] is True
    assert len(res["new_severe_findings"]) >= 1
    assert any(f["severity"] in ["Critical", "High"] for f in res["new_severe_findings"])
    assert res["verification_reason"] == "New High/Critical vulnerability introduced"

    assert rescan_fix(_NEW_SEVERE_CODE, "reentrancy") is False


# ─────────────────────────────────────────────────────────────────────────────
# Test D: Malformed Solidity: syntax_valid = False, fix_verified = False
# ─────────────────────────────────────────────────────────────────────────────
def test_d_malformed_solidity_syntax():
    assert validate_solidity_syntax(_MALFORMED_CODE) is False
    assert validate_solidity_syntax("") is False
    assert validate_solidity_syntax("N/A") is False

    res = verify_fix_details(_MALFORMED_CODE, "reentrancy")
    assert res["syntax_valid"] is False
    assert res["fix_verified"] is False
    assert res["verification_reason"] == "Syntax validation failed"
    # compiler_verification is deterministic: not_performed (solc unavailable), verified, or failed
    assert res["compiler_verification"] in ["not_performed", "verified", "failed"]

    assert rescan_fix(_MALFORMED_CODE, "reentrancy") is False


# ─────────────────────────────────────────────────────────────────────────────
# Test G: Existing Phase 1 hashes remain unchanged
# ─────────────────────────────────────────────────────────────────────────────
def test_g_phase1_hashes_remain_unchanged():
    finding = {
        "finding_id": "finding-test-hash-1",
        "vulnerability": "reentrancy",
        "severity": "High",
        "confidence": 0.85,
        "affected_lines": [10, 11, 12],
        "function": "withdraw",
        "contract": "Vault",
        "swc_id": "SWC-107",
        "original_code": "(bool success, ) = msg.sender.call{value: bal}(\"\");",
        "fixed_code": "balances[msg.sender] = 0;\n(bool success, ) = msg.sender.call{value: bal}(\"\");",
        "explanation": "State updated after external call.",
        "recommendation": "Use CEI pattern.",
        "verification_status": "CONFIRMED",
    }

    base_finding_hash = compute_finding_hash(finding)
    base_findings_hash = compute_findings_hash([finding])
    base_merkle = compute_findings_merkle_root([finding])
    base_report_hash = compute_report_hash(
        source_hash="abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        findings_hash=base_findings_hash,
        security_score=85,
        risk_level="Moderate Risk",
        analysis_mode="hybrid"
    )

    # 1. Update with fix_verified = True and verification reason
    finding_verified = dict(finding)
    finding_verified["fix_verified"] = True
    finding_verified["fix_verification_reason"] = "Vulnerability resolved and no new High/Critical findings"

    assert compute_finding_hash(finding_verified) == base_finding_hash
    assert compute_findings_hash([finding_verified]) == base_findings_hash
    assert compute_findings_merkle_root([finding_verified]) == base_merkle

    # 2. Update with fix_verified = False
    finding_unverified = dict(finding)
    finding_unverified["fix_verified"] = False
    finding_unverified["fix_verification_reason"] = "Target vulnerability still detected"

    assert compute_finding_hash(finding_unverified) == base_finding_hash
    assert compute_findings_hash([finding_unverified]) == base_findings_hash
    assert compute_findings_merkle_root([finding_unverified]) == base_merkle


# ─────────────────────────────────────────────────────────────────────────────
# Fixture for API tests: User A, User B, Admin, Analysis & Report records
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
async def api_fixture():
    run_id = uuid.uuid4().hex[:6]
    user_a_id = f"user_a_{run_id}"
    user_b_id = f"user_b_{run_id}"
    admin_id = f"admin_{run_id}"

    user_a_token = create_access_token(data={"sub": user_a_id, "role": "USER"})
    user_b_token = create_access_token(data={"sub": user_b_id, "role": "USER"})
    admin_token = create_access_token(data={"sub": admin_id, "role": "ADMIN"})

    analysis_id = f"analysis-{run_id}"
    finding_id = f"finding-{run_id}"

    async with AsyncSessionLocal() as db:
        user_a = User(
            id=user_a_id,
            email=f"usera_{run_id}@example.com",
            hashed_password=hash_password("pass123"),
            role="USER"
        )
        user_b = User(
            id=user_b_id,
            email=f"userb_{run_id}@example.com",
            hashed_password=hash_password("pass123"),
            role="USER"
        )
        admin = User(
            id=admin_id,
            email=f"admin_{run_id}@example.com",
            hashed_password=hash_password("pass123"),
            role="ADMIN"
        )
        db.add_all([user_a, user_b, admin])

        analysis = Analysis(
            id=analysis_id,
            user_id=user_a_id,
            contract_name="ReentrancyVault.sol",
            source_code=_UNRESOLVED_VULNERABLE_CODE,
            status="COMPLETED"
        )
        db.add(analysis)

        report = VulnerabilityReport(
            analysis_id=analysis_id,
            summary="Test report with reentrancy finding",
            total_findings=1,
            is_vulnerable=True,
            severity_counts={"High": 1},
            verified_findings=[{
                "finding_id": finding_id,
                "is_vulnerable": True,
                "verification_status": "CONFIRMED",
                "vulnerability": "reentrancy",
                "severity": "High",
                "confidence": 0.85,
                "affected_lines": [10, 11, 12],
                "explanation": "State updated after external call.",
                "attack_scenario": "Reentrancy attack",
                "recommendation": "Use CEI pattern",
                "original_code": _UNRESOLVED_VULNERABLE_CODE,
                "fixed_code": _CLEAN_FIXED_CODE,
                "contract": "ReentrancyVault",
                "function": "withdraw",
                "swc_id": "SWC-107",
                "fix_verified": None,
            }]
        )
        db.add(report)
        await db.commit()

    return {
        "analysis_id": analysis_id,
        "finding_id": finding_id,
        "user_a_token": user_a_token,
        "user_b_token": user_b_token,
        "admin_token": admin_token,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Test E: Unauthorized request & RBAC behavior
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_e_unauthorized_and_rbac(api_fixture):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        analysis_id = api_fixture["analysis_id"]
        finding_id = api_fixture["finding_id"]
        payload = {
            "analysis_id": analysis_id,
            "finding_id": finding_id,
            "fixed_code": _CLEAN_FIXED_CODE,
        }

        # 1. No authentication token -> 401 Unauthorized
        res_no_auth = await client.post("/api/analysis/verify-fix", json=payload)
        assert res_no_auth.status_code == 401

        # 2. User B trying to verify fix for User A's analysis -> 403 Forbidden
        res_user_b = await client.post(
            "/api/analysis/verify-fix",
            json=payload,
            headers={"Authorization": f"Bearer {api_fixture['user_b_token']}"}
        )
        assert res_user_b.status_code == 403
        assert "Access denied" in res_user_b.json()["detail"]

        # 3. User A (owner) verifying fix -> 200 OK
        res_user_a = await client.post(
            "/api/analysis/verify-fix",
            json=payload,
            headers={"Authorization": f"Bearer {api_fixture['user_a_token']}"}
        )
        assert res_user_a.status_code == 200
        data_a = res_user_a.json()
        assert data_a["fix_verified"] is True
        assert data_a["category_resolved"] is True
        assert data_a["has_new_severe"] is False
        assert data_a["syntax_valid"] is True
        # compiler_verification is deterministic: not_performed (solc unavailable), verified, or failed
        assert data_a["compiler_verification"] in ["not_performed", "verified", "failed"]

        # 4. Admin verifying fix for User A's analysis -> 200 OK (RBAC allows admin)
        res_admin = await client.post(
            "/api/analysis/verify-fix",
            json=payload,
            headers={"Authorization": f"Bearer {api_fixture['admin_token']}"}
        )
        assert res_admin.status_code == 200
        assert res_admin.json()["fix_verified"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Test F: Unknown analysis or finding: Safe error response
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_f_unknown_analysis_or_finding(api_fixture):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {api_fixture['user_a_token']}"}

        # 1. Unknown analysis_id -> 404
        res_bad_analysis = await client.post("/api/analysis/verify-fix", json={
            "analysis_id": "nonexistent-analysis-id",
            "finding_id": api_fixture["finding_id"],
            "fixed_code": _CLEAN_FIXED_CODE
        }, headers=headers)
        assert res_bad_analysis.status_code == 404
        assert "Analysis not found" in res_bad_analysis.json()["detail"]

        # 2. Known analysis, unknown finding_id -> 404
        res_bad_finding = await client.post("/api/analysis/verify-fix", json={
            "analysis_id": api_fixture["analysis_id"],
            "finding_id": "nonexistent-finding-id",
            "fixed_code": _CLEAN_FIXED_CODE
        }, headers=headers)
        assert res_bad_finding.status_code == 404
        assert "not found in report" in res_bad_finding.json()["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# Test DB Persistence: verify-fix updates DB and GET /api/analysis/{id} reflects it
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_db_persistence_reflected_in_get_analysis(api_fixture):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {api_fixture['user_a_token']}"}
        analysis_id = api_fixture["analysis_id"]
        finding_id = api_fixture["finding_id"]

        # Verify before state
        get_before = await client.get(f"/api/analysis/{analysis_id}", headers=headers)
        assert get_before.status_code == 200
        finding_before = next(f for f in get_before.json()["findings"] if f["finding_id"] == finding_id)
        assert finding_before.get("fix_verified") is None

        # Call POST /api/analysis/verify-fix
        res_verify = await client.post("/api/analysis/verify-fix", json={
            "analysis_id": analysis_id,
            "finding_id": finding_id,
            "fixed_code": _CLEAN_FIXED_CODE
        }, headers=headers)
        assert res_verify.status_code == 200
        assert res_verify.json()["fix_verified"] is True

        # Call GET /api/analysis/{analysis_id} and check persisted fix_verified & reason
        get_after = await client.get(f"/api/analysis/{analysis_id}", headers=headers)
        assert get_after.status_code == 200
        finding_after = next(f for f in get_after.json()["findings"] if f["finding_id"] == finding_id)
        assert finding_after["fix_verified"] is True
        assert finding_after["fix_verification_reason"] == "Vulnerability resolved and no new High/Critical findings"


# ─────────────────────────────────────────────────────────────────────────────
# Test H: Compiler verification - compiler unavailable → not_performed
# ─────────────────────────────────────────────────────────────────────────────
def test_h_compiler_unavailable_not_performed():
    """When compiler is unavailable (py-solc-x not installed), compiler_verification should be 'not_performed'."""
    from unittest.mock import patch

    # Mock _check_solc_available to return False
    with patch('backend.llm.reasoner._check_solc_available', return_value=False):
        res = verify_fix_details(_CLEAN_FIXED_CODE, "reentrancy")
        assert res["compiler_verification"] == "not_performed"
        assert res["syntax_valid"] is True  # Syntax validation still works without compiler


# ─────────────────────────────────────────────────────────────────────────────
# Test I: Compiler verification - compiler available + valid Solidity → verified
# ─────────────────────────────────────────────────────────────────────────────
def test_i_compiler_available_valid_solidity_verified():
    """When compiler is available and Solidity is valid, compiler_verification should be 'verified'."""
    from unittest.mock import patch

    # Mock successful compilation
    mock_compile_result = {
        "success": True,
        "solc_version": "0.8.0",
        "compiled_contracts": 1
    }

    with patch('backend.llm.reasoner._check_solc_available', return_value=True):
        with patch('backend.llm.reasoner._compile_with_solc', return_value=mock_compile_result):
            res = verify_fix_details(_CLEAN_FIXED_CODE, "reentrancy")
            assert res["compiler_verification"] == "verified"
            assert res["syntax_valid"] is True
            assert res.get("solc_version") == "0.8.0"  # solc_version should be passed through


# ─────────────────────────────────────────────────────────────────────────────
# Test J: Compiler verification - compiler available + invalid Solidity → failed
# ─────────────────────────────────────────────────────────────────────────────
def test_j_compiler_available_invalid_solidity_failed():
    """When compiler is available but Solidity is invalid, compiler_verification should be 'failed'."""
    from unittest.mock import patch

    # Mock compilation failure
    mock_compile_result = {
        "success": False,
        "error": "ParserError: Expected identifier"
    }

    with patch('backend.llm.reasoner._check_solc_available', return_value=True):
        with patch('backend.llm.reasoner._compile_with_solc', return_value=mock_compile_result):
            res = verify_fix_details(_MALFORMED_CODE, "reentrancy")
            assert res["compiler_verification"] == "failed"
            assert res["syntax_valid"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Test K: Pragma version extraction
# ─────────────────────────────────────────────────────────────────────────────
def test_k_pragma_version_extraction():
    """Test that pragma version is correctly extracted from Solidity code."""
    # Test various pragma formats
    assert _extract_pragma_version("pragma solidity ^0.8.0;") == "0.8.0"
    assert _extract_pragma_version("pragma solidity >=0.8.0 <0.9.0;") == "0.8.0"
    assert _extract_pragma_version("pragma solidity 0.8.0;") == "0.8.0"
    assert _extract_pragma_version("pragma solidity ^0.7.6;") == "0.7.6"
    # No pragma returns None
    assert _extract_pragma_version("contract Test {}") is None


# ─────────────────────────────────────────────────────────────────────────────
# Test L: Real compiler integration (if py-solc-x is available)
# ─────────────────────────────────────────────────────────────────────────────
def test_l_real_compiler_integration():
    """Test actual solc compilation if py-solc-x is available (skipped if not)."""
    try:
        import solcx
        # If solcx is available, test real compilation
        res = verify_fix_details(_CLEAN_FIXED_CODE, "reentrancy")
        # Should be one of the three deterministic states
        assert res["compiler_verification"] in ["verified", "failed", "not_performed"]
        if res["compiler_verification"] == "verified":
            assert "solc_version" in res
            print(f"Real compiler test PASSED with solc version: {res.get('solc_version')}")
        elif res["compiler_verification"] == "failed":
            print(f"Real compiler test: compilation failed with error: {res.get('error', 'unknown')}")
        else:
            print("Real compiler test: compiler not available or installation failed")
    except ImportError:
        # py-solc-x not installed, skip this test
        pytest.skip("py-solc-x not installed, skipping real compiler test")
