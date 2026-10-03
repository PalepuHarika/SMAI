import sys
import os
import json
import asyncio
import time
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, '.')
from backend.pipeline import SecurityPipeline

# 10-contract held-out subset
HELD_OUT_CONTRACTS = [
    "Eval_Reentrancy_01.sol",
    "Eval_Safe_01.sol",
    "Eval_TxOrigin_01.sol",
    "Eval_Timestamp_01.sol",
    "Eval_UncheckedCall_01.sol",
    "Eval_MissingAccessControl_01.sol",
    "Eval_Safe_MissingAccessControl_02.sol",
    "Eval_Delegatecall_01.sol",
    "Eval_Selfdestruct_01.sol",
    "Eval_Safe_02.sol",
]

def load_ground_truth() -> Dict:
    """Load ground truth from datasets/held_out/ground_truth.json"""
    gt_path = Path("datasets/held_out/ground_truth.json")
    with open(gt_path, 'r') as f:
        return json.load(f)

def calculate_metrics(results: List[Dict], ground_truth: Dict) -> Dict:
    """Calculate TP, TN, FP, FN, Accuracy, Precision, Recall, F1"""
    tp = tn = fp = fn = 0
    
    for contract_name, result in results:
        gt = ground_truth.get(contract_name, {})
        expected_vuln = gt.get("is_vulnerable", False)
        expected_cats = set(gt.get("expected_vulnerabilities", []))
        
        # Get actual detected categories (excluding floating-pragma which is informational)
        actual_cats = set()
        for f in result.get("findings", []):
            cat = f.get("vulnerability", "")
            if cat != "floating-pragma" and cat != "missing-zero-check":
                actual_cats.add(cat)
        
        # Contract is vulnerable if it has any of the expected vulnerability categories
        predicted_vuln = len(actual_cats.intersection(expected_cats)) > 0 if expected_cats else len(actual_cats) > 0
        
        if expected_vuln and predicted_vuln:
            tp += 1
        elif not expected_vuln and not predicted_vuln:
            tn += 1
        elif not expected_vuln and predicted_vuln:
            fp += 1
        elif expected_vuln and not predicted_vuln:
            fn += 1
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1
    }

async def run_mode(pipeline: SecurityPipeline, mode: str, contracts: List[str], 
                  ground_truth: Dict, contracts_dir: Path) -> Dict:
    """Run evaluation for a single mode"""
    print(f"\n{'='*60}")
    print(f"Running Mode: {mode.upper()}")
    print(f"{'='*60}")
    
    results = []
    start_time = time.time()
    
    for contract_name in contracts:
        filepath = contracts_dir / contract_name
        if not filepath.exists():
            print(f"Warning: {contract_name} not found, skipping")
            continue
        
        print(f"\n[{mode.upper()}] Scanning {contract_name}...")
        contract_start = time.time()
        
        with open(filepath, 'r') as f:
            code = f.read()
        
        try:
            report = await pipeline.scan(code, contract_name, mode=mode)
            contract_time = time.time() - contract_start
            
            # Extract findings data
            findings_data = []
            for finding in report.findings:
                findings_data.append({
                    "vulnerability": finding.vulnerability,
                    "swc_id": getattr(finding, "swc_id", None),
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "static_confidence": finding.static_confidence,
                    "is_vulnerable": finding.is_vulnerable,
                    "verification_status": finding.verification_status,
                    "fallback_used": finding.fallback_used,
                    "model_used": finding.model_used,
                })
            
            result = {
                "contract_id": contract_name,
                "ground_truth": ground_truth.get(contract_name, {}),
                "mode": mode,
                "predicted_vulnerability": report.is_vulnerable,
                "total_findings": report.total_findings,
                "security_score": report.security_score,
                "risk_level": report.risk_level,
                "findings": findings_data,
                "runtime_seconds": contract_time
            }
            
            results.append((contract_name, result))
            print(f"  Score: {report.security_score} | Risk: {report.risk_level} | Findings: {report.total_findings} | Time: {contract_time:.2f}s")
            
        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()
            results.append((contract_name, {"error": str(e)}))
    
    total_time = time.time() - start_time
    
    # Calculate metrics
    metrics = calculate_metrics(results, ground_truth)
    metrics["total_runtime_seconds"] = total_time
    metrics["dataset_size"] = len(results)
    
    print(f"\n{mode.upper()} Mode Metrics:")
    print(f"  TP: {metrics['true_positives']}")
    print(f"  TN: {metrics['true_negatives']}")
    print(f"  FP: {metrics['false_positives']}")
    print(f"  FN: {metrics['false_negatives']}")
    print(f"  Accuracy: {metrics['accuracy']:.3f}")
    print(f"  Precision: {metrics['precision']:.3f}")
    print(f"  Recall: {metrics['recall']:.3f}")
    print(f"  F1: {metrics['f1_score']:.3f}")
    print(f"  Total Runtime: {total_time:.2f}s")
    
    return {
        "mode": mode,
        "metrics": metrics,
        "results": [r for _, r in results]
    }

async def main():
    print("="*60)
    print("SMAI Final Evaluation - RAG Only Mode")
    print("="*60)
    
    # Load ground truth
    ground_truth = load_ground_truth()
    print(f"\nLoaded ground truth for {len(ground_truth)} contracts")
    
    # Initialize pipeline
    pipeline = SecurityPipeline()
    
    # Set contracts directory
    contracts_dir = Path("datasets/held_out")
    
    # Run RAG mode only (no LLM)
    try:
        result = await run_mode(pipeline, "A", HELD_OUT_CONTRACTS, ground_truth, contracts_dir)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Save results
    output_dir = Path("research/evaluation")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save detailed results
    detailed_results = {
        "evaluation_metadata": {
            "evaluation_date": "2026-10-03",
            "repository_commit": "dd27705",
            "dataset": "held_out_10_contract_subset",
            "contracts": HELD_OUT_CONTRACTS,
            "mode": "rag_only"
        },
        "results": result
    }
    
    with open(output_dir / "rag_only_evaluation.json", 'w') as f:
        json.dump(detailed_results, f, indent=2)
    
    print("\n" + "="*60)
    print("EVALUATION COMPLETE")
    print("="*60)
    print(f"Results saved to {output_dir}/rag_only_evaluation.json")

if __name__ == "__main__":
    asyncio.run(main())
