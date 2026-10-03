# Confidence Metrics Methodology

## Overview

The SMAI system uses an **evidence/verification score** as the confidence metric. This is NOT an empirically calibrated probability in the statistical sense.

## Confidence Calculation Function

The confidence is computed by `compute_calibrated_confidence()` in `backend/llm/reasoner.py`:

```python
def compute_calibrated_confidence(
    static_confidence: Optional[float],  # From static analyzer
    rag_similarity: Optional[float],    # TF-IDF cosine similarity (0.0-1.0)
    llm_confidence: Optional[float],     # LLM self-reported confidence
    has_protection_evidence: bool = False,
    is_confirmed: bool = True
) -> float
```

## Weighting Scheme

- w_static = 0.35 (35% weight)
- w_rag = 0.25 (25% weight)
- w_llm = 0.40 (40% weight)

The weights are dynamically renormalized based on which evidence sources are available.

## Calculation Process

1. **Base Score**: Weighted average of available evidence sources
   - If all available: `base = (0.35*static + 0.25*rag + 0.40*llm)`
   - If only static: `base = static_confidence`
   - If none available: `base = 0.10` (minimum baseline)

2. **Modifiers**:
   - If `has_protection_evidence` is True: `base *= 0.6` (reduce confidence)
   - If `is_confirmed` is False: `base = min(base, 0.45)` (cap at 45%)

3. **Final Bounds**: Clamped to [0.10, 0.95]

## Mode-Specific Behavior

### RAG Only Mode (Mode A)
- static_confidence: Available (from static analyzer)
- rag_similarity: None (not used as evidence in this mode)
- llm_confidence: None (no LLM verification)
- is_confirmed: True (all findings marked CONFIRMED)
- **Result**: Confidence ≈ static_confidence (with 0.35 weight renormalized to 1.0)

### AI Only Mode (Mode B)
- static_confidence: Available
- rag_similarity: None (no RAG retrieval)
- llm_confidence: Available (from LLM self-report)
- is_confirmed: Based on LLM decision
- **Result**: Weighted combination of static + LLM

### Hybrid Mode (Mode C)
- static_confidence: Available
- rag_similarity: Available (cosine similarity from RAG)
- llm_confidence: Available
- is_confirmed: Based on LLM decision
- **Result**: Weighted combination of all three sources

## Important Notes

1. **Not Calibrated**: The confidence score is NOT empirically calibrated. There is no calibration dataset, no reliability diagrams, and no temperature scaling.

2. **RAG Similarity ≠ Probability**: The RAG similarity score is TF-IDF cosine similarity (0.0-1.0), which represents retrieval evidence, NOT vulnerability probability.

3. **LLM Self-Reported**: The LLM confidence is self-reported by the model, not empirically validated.

4. **Brier/ECE/MCE**: These calibration metrics were computed using a mocked evaluation script (`tests/evaluate_calibration.py`). They do NOT represent empirical calibration on real data.

## Statistical Calibration Metrics

The existing Brier Score, ECE, and MCE values in `final_metrics.json` were generated from:

- Script: `tests/evaluate_calibration.py`
- Method: Mocked LLM responses (simulated confidence values)
- NOT representative of actual model behavior

Therefore, these values should NOT be interpreted as evidence of calibration. They are historical artifacts from a test script.

## Recommendation

For research purposes, the confidence score should be described as:
- "Evidence-based verification score"
- "Composite confidence from static analysis, RAG retrieval, and LLM verification"
- NOT "Calibrated probability" or "Empirically calibrated confidence"
