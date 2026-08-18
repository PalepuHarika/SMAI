#!/bin/bash
echo "Waiting for qwen2.5-coder:latest to finish pulling..."
while ! docker exec scanner_ollama ollama list | grep -q "qwen2.5-coder:latest"; do
    sleep 10
done
echo "Model pull complete! Executing test suite..."
cd /home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner
PYTHONPATH=. venv/bin/python3 scripts/run_test_suite.py
echo "Generating Markdown report..."
PYTHONPATH=. venv/bin/python3 scripts/generate_llm_report.py
echo "Done!"
