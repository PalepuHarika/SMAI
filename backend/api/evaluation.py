import json
from pathlib import Path
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/evaluation", tags=["Evaluation"])
RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"

@router.get("/metrics")
async def get_evaluation_metrics():
    path = RESULTS_DIR / "evaluation_dashboard_data.json"
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail=(
                "Evaluation results not found. From the repository root, run "
                "`python scripts/run_scientific_eval.py` followed by "
                "`python scripts/generate_metrics.py`."
            ),
        )
    
    with open(path, "r") as f:
        data = json.load(f)
    return data

@router.get("/raw")
async def get_raw_evaluation():
    path = RESULTS_DIR / "raw_evaluation_results.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Raw results not found.")
    
    with open(path, "r") as f:
        data = json.load(f)
    return data
