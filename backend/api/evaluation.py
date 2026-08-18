import json
import os
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/evaluation", tags=["Evaluation"])

@router.get("/metrics")
async def get_evaluation_metrics():
    path = "results/evaluation_dashboard_data.json"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Evaluation results not found. Run the scientific evaluation script first.")
    
    with open(path, "r") as f:
        data = json.load(f)
    return data

@router.get("/raw")
async def get_raw_evaluation():
    path = "results/raw_evaluation_results.json"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Raw results not found.")
    
    with open(path, "r") as f:
        data = json.load(f)
    return data
