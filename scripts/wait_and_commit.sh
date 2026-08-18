#!/bin/bash
echo "Waiting for task-809 to finish..."
while pgrep -f run_test_suite.py > /dev/null; do
    sleep 10
done
sleep 10
cd /home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner
git add test_suite_results.json llm_baseline_report.md
git commit -m "docs: Generate 7B LLM Baseline Report"
git push origin main
echo "Done!"
