import pytest
from backend.pipeline import calculate_security_score
from backend.core.finding import VerifiedVulnerability

def make_finding(severity: str, confidence: float = 1.0, status: str = "CONFIRMED", id_num: int = 1) -> VerifiedVulnerability:
    return VerifiedVulnerability(
        finding_id=f"f{id_num}",
        is_vulnerable=status == "CONFIRMED",
        verification_status=status,
        vulnerability="test",
        severity=severity,
        confidence=confidence,
        affected_lines=[1],
        explanation="",
        attack_scenario="",
        recommendation="",
        original_code="",
        fixed_code="",
        contract="Test",
        function="test"
    )

def test_zero_findings():
    score, risk = calculate_security_score([])
    assert score == 100
    assert risk == "Low Risk"

def test_score_spam_resistance():
    # 100 Informational findings
    findings = [make_finding("Informational", id_num=i) for i in range(100)]
    score, risk = calculate_security_score(findings)
    # 100 * 1.0 = 100 points, but capped at 10.
    assert score == 90
    assert risk == "Low Risk"
    
def test_mixed_severity_spam():
    # 100 Info, 100 Low, 100 Medium
    findings = []
    findings += [make_finding("Informational", id_num=i) for i in range(100)]
    findings += [make_finding("Low", id_num=i+100) for i in range(100)]
    findings += [make_finding("Medium", id_num=i+200) for i in range(100)]
    
    score, risk = calculate_security_score(findings)
    # Caps: Info(10) + Low(20) + Medium(30) = 60 deduction.
    # Score = 40.
    assert score == 40
    assert risk == "High Risk"
    
def test_critical_spam():
    # 10 Critical findings
    findings = [make_finding("Critical", id_num=i) for i in range(10)]
    score, risk = calculate_security_score(findings)
    # 10 * 25.0 = 250, capped at 100.
    # Score = 0.
    assert score == 0
    assert risk == "Critical Risk"

def test_severity_floor():
    # 1 Critical finding, score is 75 (Moderate), but floor pushes to Critical
    findings = [make_finding("Critical", 1.0)]
    score, risk = calculate_security_score(findings)
    assert score == 75
    assert risk == "Critical Risk"

def test_order_independence():
    f1 = make_finding("Critical", 1.0, id_num=1)
    f2 = make_finding("Informational", 1.0, id_num=2)
    f3 = make_finding("Low", 0.5, id_num=3)
    
    s1, r1 = calculate_security_score([f1, f2, f3])
    s2, r2 = calculate_security_score([f3, f1, f2])
    
    assert s1 == s2
    assert r1 == r2

def test_confidence_monotonicity():
    f_low_conf = make_finding("High", 0.1)
    f_high_conf = make_finding("High", 0.9)
    
    s1, _ = calculate_security_score([f_low_conf])
    s2, _ = calculate_security_score([f_high_conf])
    
    assert s2 < s1

def test_unverified_interaction():
    # Unverified findings have their confidence capped at 0.45 inside reasoner.py
    # But calculate_security_score just multiplies weight * conf.
    # We simulate the 0.45 confidence here.
    f_verified = make_finding("Medium", 0.9, "CONFIRMED")
    f_unverified = make_finding("Medium", 0.45, "UNVERIFIED")
    
    s1, _ = calculate_security_score([f_verified])
    s2, _ = calculate_security_score([f_unverified])
    
    # Verified should deduct more, meaning a lower score.
    assert s1 < s2
    
def test_invalid_confidence():
    f_invalid = make_finding("Medium"); f_invalid.__dict__["confidence"] = float("nan")
    s, r = calculate_security_score([f_invalid])
    # Should fallback to 0.8 -> 8.0 * 0.8 = 6.4 deduction -> 94
    assert s == 94
