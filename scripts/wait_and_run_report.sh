#!/bin/bash
echo "Waiting for task-807 to finish by checking python process..."
while pgrep -f run_test_suite.py > /dev/null; do
    sleep 5
done
echo "Test suite completed! Generating Markdown report..."
cd /home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner
PYTHONPATH=. venv/bin/python3 scripts/generate_llm_report.py
echo "Done!"
