#!/bin/bash
set -e
echo "Starting A->Z Evaluation Pipeline..."

echo "1. Running Scientific Eval (Modes A, B, C)..."
PYTHONPATH=. venv/bin/python3 scripts/run_scientific_eval.py

echo "2. Running P0 Ablation (Mode C, P0)..."
PYTHONPATH=. venv/bin/python3 scripts/run_p0_ablation.py

echo "3. Merging Results..."
PYTHONPATH=. venv/bin/python3 scripts/merge_results.py

echo "4. Generating Metrics..."
PYTHONPATH=. venv/bin/python3 scripts/generate_metrics.py

echo "ALL DONE!"
