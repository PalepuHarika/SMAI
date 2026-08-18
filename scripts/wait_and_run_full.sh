#!/bin/bash
cd /home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner
PYTHONPATH=. venv/bin/python3 scripts/run_test_suite.py
PYTHONPATH=. venv/bin/python3 scripts/generate_llm_report.py
git add test_suite_results.json llm_baseline_report.md backend/core/finding.py backend/llm/reasoner.py
git commit -m "docs: Generate verified 7B LLM baseline report without fallback"
git push origin main
