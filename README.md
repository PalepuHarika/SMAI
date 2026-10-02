# SMAI - Smart Contract Security Analysis with AI

SMAI is a research-grade smart contract vulnerability scanner that combines static analysis, RAG-based security knowledge retrieval, and LLM verification to identify security issues in Solidity smart contracts.

## Architecture

The system follows a multi-phase pipeline:

1. **Static Analysis**: Rule-based detection of common Solidity vulnerabilities (reentrancy, tx.origin, unchecked calls, etc.)
2. **RAG Retrieval**: Security knowledge base lookup for vulnerability context and mitigation patterns
3. **LLM Verification**: Qwen2.5-Coder model for grounded vulnerability confirmation with prompt injection protection
4. **Security Scoring**: Evidence-based scoring (0-100) with severity floors and spam resistance
5. **Integrity/Provenance**: SHA-256/Keccak-256 hashing, finding canonicalization, Merkle trees, report hashing
6. **Fix Verification**: Static re-analysis of proposed fixes with category resolution and new severe finding detection
7. **Blockchain Audit Registry**: Optional on-chain audit registration (EVM-compatible, uses AuditRegistry contract)

## Supported Vulnerability Classes

- Reentrancy (SWC-107)
- Unchecked Low-Level Calls (SWC-104)
- tx.origin Authentication (SWC-115)
- Timestamp Dependence (SWC-116)
- Unprotected Selfdestruct (SWC-106)
- Dangerous Delegatecall (SWC-112)
- Uninitialized Storage Pointers (SWC-109)
- Missing Zero Address Validation (SWC-136)
- Floating Pragma (SWC-103)
- ECRecover Validation (SWC-117)
- Integer Overflow (SWC-101)
- Missing Access Control (SWC-105)

## Analysis Modes

The system supports three analysis modes:

- **Hybrid**: Static Analysis + RAG + AI Verification (recommended)
- **RAG Only**: Static Analysis + Security Knowledge Retrieval (no AI)
- **AI Only**: Static Analysis + Qwen AI Verification (no RAG)

Static classification (category, SWC ID, severity, affected lines) remains authoritative in all modes. The LLM does not override static detector decisions.

## Components

### Backend (FastAPI)
- `backend/analyzer/`: Static analysis engine
- `backend/rag/`: Knowledge base and retrieval
- `backend/llm/`: LLM verification with Ollama integration
- `backend/core/`: Security scoring, integrity hashing, blockchain registry
- `backend/api/`: REST API endpoints
- `backend/db/`: PostgreSQL database models

### Frontend (React + TypeScript + Vite)
- Monaco Editor for Solidity code editing
- Analysis mode selector
- Report visualization with source highlighting
- Finding navigation and evidence display
- Fix verification interface
- Blockchain status display

### Tests
- Static analyzer tests (35 tests)
- RAG retrieval tests (8 tests)
- Integrity hashing tests (13 tests)
- Fix verification tests (8 tests)
- Blockchain registry tests (15 tests)
- Security scoring tests (9 tests)
- Pipeline integration tests (4 tests)
- LLM adversarial tests (3 tests)

## Quick Start with Docker

```bash
docker compose up --build
```

This starts:
- Ollama (with qwen2.5-coder:latest model)
- FastAPI backend on port 8000
- React frontend on port 5173

## Manual Setup

### Backend
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Ollama
```bash
ollama pull qwen2.5-coder:latest
ollama serve
```

## Testing

Run targeted test suites:

```bash
# Static analyzer
pytest tests/test_static_analyzer.py -v

# RAG
pytest tests/test_rag.py tests/test_rag_adversarial.py -v

# Integrity
pytest tests/test_integrity.py -v

# Fix verification
pytest tests/test_fix_verification.py -v

# Blockchain registry
pytest tests/test_blockchain_registry.py -v

# Security scoring
pytest tests/test_score_hardening.py -v

# Pipeline
pytest tests/test_pipeline.py -v

# LLM adversarial
pytest tests/test_llm_adversarial.py -v
```

## Security Semantics

- **Static Authority**: The static analyzer is authoritative for vulnerability category, SWC ID, severity, and affected lines. The LLM must not override static classification.
- **RAG Similarity**: RAG similarity is retrieval evidence, not a calibrated probability. It must not be treated as confidence.
- **LLM Confidence**: LLM confidence is self-reported and not empirically calibrated unless evidence exists.
- **Security Score**: An evidence-based score from 0-100, not a "percentage of security."
- **Prompt Injection Protection**: Source code delimiters and explicit directives prevent prompt injection from contract code.

## Performance

- LLM timeout: 120s (connect: 10s)
- num_predict: 512 tokens (reduced from 1024)
- Fix verification uses asyncio.to_thread to avoid blocking
- Sequential verification by default (Ollama stability)

## Integrity / Provenance

Phase 1 integrity features:
- Source hash (SHA-256)
- Source hash (Keccak-256, optional)
- Finding hash (canonical representation)
- Findings hash (deterministic collection hash)
- Findings Merkle root
- Report hash (canonical report digest)
- Ephemeral IDs and timestamps excluded from canonical content

## Fix Verification

Fix verification flow:
1. Validates syntax of proposed fixed code
2. Reruns static analysis on fixed code
3. Checks if original vulnerability category is resolved
4. Detects newly introduced Critical/High findings
5. Preserves original vulnerability category
6. Returns verification details with compiler_verification = "not_performed" (solc not used)

Does not claim formal verification. If solc is unavailable, reports compiler_verification as not_performed.

## Blockchain Audit Registry

Optional trust/provenance layer for on-chain audit registration. Not required for vulnerability scanning.

Configuration (optional):
- `AUDIT_REGISTRY_ADDRESS`: Contract address
- `AUDIT_REGISTRY_RPC_URL`: RPC endpoint
- `AUDIT_REGISTRY_PRIVATE_KEY`: Signer private key
- `AUDIT_REGISTRY_CHAIN_ID`: Chain ID

Features:
- Graceful handling of missing configuration
- Register-audit endpoint
- Verify-audit endpoint
- Owner/RBAC checks
- Phase 1 hash usage
- Mock blockchain support in tests

## Limitations

- Tested benchmark performance on specific test suites; general real-world detection capability may vary.
- LLM verification depends on Ollama availability and model quality.
- Fix verification does not perform formal verification or compiler checks.
- Blockchain registration requires manual configuration and web3.py.
- RAG knowledge base is curated and may not cover all vulnerability patterns.

## License

Research project. See individual component licenses for details.
