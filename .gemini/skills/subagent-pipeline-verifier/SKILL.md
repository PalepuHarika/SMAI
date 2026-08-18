---
name: subagent-pipeline-verifier
description: Multi-agent verification framework to validate the A-to-Z working of the Smart Contract Scanner pipeline. Defines agent roles, handoffs, and system bottlenecks.
---

# Subagent Pipeline Verifier

Use this skill when tasked with verifying, testing, or debugging the complete end-to-end (A-to-Z) workflow of the Smart Contract Vulnerability Scanner.

## 1. Mission & Philosophy
This skill extends the **Karpathy Guidelines** into a multi-agent testing environment. Do not test the system as a monolithic black box. Simulate a specialized subagent for each layer to ensure data flows correctly.

## 2. Multi-Agent Verification Topology
1. **The Coordinator (FastAPI Agent):** Submits payload, verifies RBAC, initiates scan.
2. **The Analyzer (Static Analysis Agent):** Parses AST, extracts lines, variables, and SWC categories.
3. **The Librarian (RAG Agent):** Fetches exact, relevant mitigation docs; excludes noise.
4. **The Skeptic (LLM Reasoning Agent):** Evaluates static finding + RAG context. Writes Attack Scenario and Fixed Code.
5. **The Presentation Agent (React UI):** Renders Vulnerability Cards, Diff Views, and Severity Badges.

## 3. A-to-Z Verification Workflow
[Step 1] Coordinator → verify: 200 OK & Valid Auth Token  
[Step 2] Analyzer → verify: Valid Line Extraction & SWC Mapping  
[Step 3] Librarian → verify: Top-K Vector Retrieval Match  
[Step 4] Skeptic → verify: Valid JSON Output (No Hallucinated Syntax)  
[Step 5] UI Agent → verify: UI State Update & Diff Render  

## 4. ⚠️ BOTTLENECK NOTE (Think Before Scaling)
* **Context Overflow:** Injecting full 1,000-line contracts into the LLM crashes local VRAM. Extract *only* the vulnerable function.
* **Hallucination Amplification:** If RAG fetches the wrong standard, the LLM will confidently hallucinate a fake attack.
* **Sequential Latency:** Avoid hanging the UI. FastAPI must return HTTP 202 (Accepted) and process the scan in the background.
* **JSON Serialization Crashes:** Use strict grammar flags. A dropped comma from the LLM will crash the Pydantic API layer.
