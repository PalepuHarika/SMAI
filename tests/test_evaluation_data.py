import asyncio
import json

import pytest
from fastapi import HTTPException

from backend.api import evaluation
from scripts.generate_metrics import compute_metrics


def test_metrics_endpoint_reads_configured_results_directory(tmp_path, monkeypatch):
    expected = {"Mode A": {"metrics": {"accuracy": 0.5}}}
    (tmp_path / "evaluation_dashboard_data.json").write_text(json.dumps(expected))
    monkeypatch.setattr(evaluation, "RESULTS_DIR", tmp_path)

    assert asyncio.run(evaluation.get_evaluation_metrics()) == expected


def test_metrics_endpoint_keeps_missing_data_protection_and_gives_pipeline_steps(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(evaluation, "RESULTS_DIR", tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(evaluation.get_evaluation_metrics())

    assert exc_info.value.status_code == 404
    assert "run_scientific_eval.py" in exc_info.value.detail
    assert "generate_metrics.py" in exc_info.value.detail


def test_metrics_do_not_infer_prompt_ablation_metadata():
    summary = compute_metrics(
        [
            {
                "contract": "sample.sol",
                "mode": "B",
                "model": "model-x",
                "is_vulnerable": True,
                "fallback_used": False,
            }
        ],
        {"sample.sol": {"is_vulnerable": True}},
    )

    row = next(iter(summary.values()))
    assert row["prompt"] is None
    assert "P1" not in next(iter(summary))
    assert row["metrics"]["accuracy"] == 1.0
