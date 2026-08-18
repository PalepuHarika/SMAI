# Smart Contract Scanner Evaluation Report

## AB. FINAL RESEARCH CONCLUSIONS

**1. Does the grounding prompt improve vulnerability verification?**
**Status:** PARTIALLY SUPPORTED (Pending full P0 evaluation data)
*Evidence:* Preliminary tests with P1 show that negative verification helps reject specific context patterns (like `tx.origin` in logging), but we await the P0 vs P1 full run metrics.

**2. Does the improvement generalize across vulnerability classes?**
**Status:** INSUFFICIENT EVIDENCE
*Evidence:* The current suite has 14 contracts focusing heavily on `tx.origin` and `delegatecall`. Broader benchmarks (SmartBugs) are needed.

**3. Does Qwen 7B outperform Qwen 1.5B?**
**Status:** NOT SUPPORTED
*Evidence:* The Qwen 7B model consistently hits an infrastructure/OOM failure during grammar-constrained structured JSON generation. Therefore, its theoretical reasoning advantage cannot be realized in the current system architecture.

**4. Does RAG improve vulnerability detection?**
**Status:** INSUFFICIENT EVIDENCE
*Evidence:* The 14-contract diagnostic suite is too small to show a statistically significant delta in F1 scores between Mode B and Mode C.

**5. Does RAG improve grounding?**
**Status:** INSUFFICIENT EVIDENCE
*Evidence:* As above, RAG currently retrieves rules, but attack scenario generation remains heavily templated.

**6. What are precision, recall and F1?**
**Status:** SUPPORTED
*Evidence:* (See Evaluation Dashboard for exact figures). Baseline static analysis achieves ~80% F1, but suffers from high false-positive rates. LLM metrics depend strictly on infrastructure success.

**7. What is the false-positive rejection rate?**
**Status:** SUPPORTED
*Evidence:* The LLM correctly rejected `TC8_TxOriginFalsePositive` when constrained by the P1 prompt.

**8. What is the hallucination rate?**
**Status:** SUPPORTED
*Evidence:* Captured in the Grounding Quality tab of the dashboard.

**9. How often are attack scenarios genuinely grounded?**
**Status:** PARTIALLY SUPPORTED
*Evidence:* The LLM often resorts to generic templated responses (e.g., "Attacker exploits vulnerable pattern") when uncertain.

**10. Is confidence calibrated?**
**Status:** NOT SUPPORTED
*Evidence:* Both the static analyzer and the LLM frequently return `1.0` (100%) confidence for both True Positives and False Positives. Confidence is poorly calibrated.

**11. Is severity classification accurate?**
**Status:** PARTIALLY SUPPORTED
*Evidence:* Confusion matrices show that models can distinguish High/Critical vulnerabilities but struggle with medium vs low boundaries.

**12. Does the system generalize to external benchmark data?**
**Status:** INSUFFICIENT EVIDENCE
*Evidence:* SmartBugs Curated and DVBench evaluations are pending.

**13. Does it generalize to real-world exploited contracts?**
**Status:** INSUFFICIENT EVIDENCE
*Evidence:* DVBench evaluations are pending.

## X. DATASET-SPECIFIC RESULTS
Metrics are strictly isolated. Do not merge results across the Diagnostic Suite and SmartBugs.
