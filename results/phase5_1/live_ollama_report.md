# Phase 5.1: Live Ollama / Real LLM Validation

## 1. Environment
- **OS**: Windows (PowerShell) / WSL
- **Python**: 3.14.0
- **Database**: SQLite (Async)

## 2. Ollama Availability
**STATUS: UNAVAILABLE (NOT INSTALLED)**
- The `ollama` executable is not available in the system PATH.
- `wsl ollama` command not found.
- The default API endpoint (`http://localhost:11434/api/tags`) is unreachable (`ConnectTimeout`).

## 3. Model/Version Configuration
The SMAI backend (`backend/llm/reasoner.py`) expects the following configuration:
- **Model**: `qwen2.5-coder:latest`
- **OLLAMA_URL**: `http://localhost:11434` (configurable via environment variable)
- **Timeout**: `120.0` seconds
- **Prompt Mode**: `P1` (Chain-of-Thought JSON Schema enforcement)

**Environment Requirements to Run**:
The host system must have the Ollama service installed and running on port 11434. The model must be explicitly pulled (`ollama pull qwen2.5-coder:latest`). The system requires sufficient RAM/VRAM to load a ~4.7GB+ parameter LLM in memory to support concurrent asynchronous requests without thrashing.

## 4-18. Live Tests & Metrics
*Because the live Ollama service is uninstalled and unreachable, the live execution of the LLM verification pipeline could not be performed. Single-finding tests, multi-finding tests, 140-contract E2E evaluations, latency measurements, and prompt-injection resistance against the live model are blocked.*

## 19. Simulated vs Real Comparison
- **Simulated Metrics**:
  - Accuracy: 0.87
  - Precision: 0.84
  - Recall: 1.00
  - F1: 0.92
- **Real Metrics**:
  - `N/A` (Blocked due to environment constraints).

## 20. Error Analysis & Invariants
While the live LLM is unavailable, the SMAI pipeline aggressively intercepts `ConnectTimeout` and HTTP errors, gracefully degrading findings to the `UNVERIFIED` state (Confidence: `0.45`). The pipeline does not crash, maintaining stability as proven by the 76/76 passing baseline regression tests.

## 21. Regression Results
- Full pytest baseline: **76/76 Passed** in 15.20s.
- RAG benchmark: **20/20 Passed**.
No tests were weakened or deleted.

## 22. Limitations
The fundamental limitation of Phase 5.1 is the physical absence of the LLM service. The backend architecture successfully isolates, manages, and maps LLM IO, but the true intelligence, hallucination variance, and semantic comprehension of `qwen2.5-coder:latest` over our 140-contract evaluation set remains unknown.

## 23. Reproducibility Information
To execute the live validation, deploy SMAI on a GPU-enabled host:
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull qwen2.5-coder:latest
# Then re-run the evaluation harnesses.
```

## 24. Final Reliability Interpretation
The SMAI system is extremely mathematically and architecturally reliable (static fallback, spam-resistance, severity-floors, isolation, bounded scores). However, its dynamic accuracy relies entirely on a deterministic proxy simulated in CI. The pipeline securely handles the complete loss of the LLM component.
