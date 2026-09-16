import pytest
from backend.llm.reasoner import compute_calibrated_confidence

def test_confidence_llm_available_confident():
    # TEST 1 — LLM available and confident
    # Static = 0.88, RAG = 0.70, LLM = 0.80
    # Expected raw base: 0.35*0.88 + 0.25*0.70 + 0.40*0.80 = 0.803
    conf = compute_calibrated_confidence(
        static_confidence=0.88,
        rag_similarity=0.70,
        llm_confidence=0.80,
        has_protection_evidence=False,
        is_confirmed=True
    )
    assert abs(conf - 0.803) < 0.01

def test_confidence_llm_available_uncertain():
    # TEST 2 — LLM available but explicitly uncertain
    # Static = 0.88, RAG = 0.70, LLM = 0.50
    # Expected raw base: 0.35*0.88 + 0.25*0.70 + 0.40*0.50 = 0.683
    conf = compute_calibrated_confidence(
        static_confidence=0.88,
        rag_similarity=0.70,
        llm_confidence=0.50,
        has_protection_evidence=False,
        is_confirmed=True
    )
    assert abs(conf - 0.683) < 0.01

def test_confidence_llm_unavailable_raw_base():
    # TEST 3 — LLM unavailable (raw base check)
    # Static = 0.88, RAG = 0.70, LLM = None
    # Expected renormalized raw base approximately: (0.35/0.60)*0.88 + (0.25/0.60)*0.70 ≈ 0.805
    conf = compute_calibrated_confidence(
        static_confidence=0.88,
        rag_similarity=0.70,
        llm_confidence=None,
        has_protection_evidence=False,
        is_confirmed=True  # Testing raw base without the UNVERIFIED cap
    )
    assert abs(conf - 0.805) < 0.01

def test_confidence_llm_unavailable_unverified_cap():
    # Verify the existing UNVERIFIED cap produces: 0.45
    conf = compute_calibrated_confidence(
        static_confidence=0.88,
        rag_similarity=0.70,
        llm_confidence=None,
        has_protection_evidence=False,
        is_confirmed=False  # Apply the UNVERIFIED cap
    )
    assert conf == 0.45

def test_confidence_low_evidence():
    # Test a low-evidence case where all evidence is missing
    # Explicitly testing the conservative fallback policy of 0.10
    conf = compute_calibrated_confidence(
        static_confidence=None,
        rag_similarity=None,
        llm_confidence=None,
        has_protection_evidence=False,
        is_confirmed=True
    )
    assert conf == 0.10

def test_confidence_modifiers_independent():
    # Separately test the protection evidence modifier
    conf_base = compute_calibrated_confidence(
        static_confidence=0.88,
        rag_similarity=0.70,
        llm_confidence=0.80,
        has_protection_evidence=False,
        is_confirmed=True
    )
    
    conf_mod = compute_calibrated_confidence(
        static_confidence=0.88,
        rag_similarity=0.70,
        llm_confidence=0.80,
        has_protection_evidence=True,
        is_confirmed=True
    )
    
    # base * 0.6
    assert abs(conf_mod - (conf_base * 0.6)) < 0.01
