import json
import os
import re
import argparse

def compute_metrics(results, ground_truth):
    summary = {}
    
    for r in results:
        dataset = r.get("dataset", "Internal Diagnostic Suite")
        mode = r.get("mode", "A")
        model = r.get("model", "static")
        prompt = r.get("prompt", "P1")
        
        # Combine mode, model, prompt for the key
        if model == "static":
            key = f"{dataset} | Mode {mode} - {model}"
        else:
            key = f"{dataset} | Mode {mode} - {model} ({prompt})"
            
        if key not in summary:
            summary[key] = {
                "dataset": dataset,
                "mode": mode,
                "model": model,
                "prompt": prompt,
                "TP": 0, "TN": 0, "FP": 0, "FN": 0,
                "fallbacks": 0, "infra_failures": 0, "total": 0,
                "confidence_correct": [], "confidence_incorrect": [],
                "grounded": 0, "partially_grounded": 0, "hallucinated": 0, "generic": 0,
                "vuln_classes": {},
                "severity_matrix": {} 
            }
            
        summary[key]["total"] += 1
        
        contract = r["contract"]
        gt = ground_truth.get(contract, {})
        gt_is_vuln = gt.get("is_vulnerable", False)
        gt_category = gt.get("category", "none")
        gt_severity = gt.get("severity", "Informational")
        
        pred_is_vuln = r.get("is_vulnerable", False)
        fallback = r.get("fallback_used", False)
        
        if fallback and model != "static":
            summary[key]["infra_failures"] += 1
            summary[key]["fallbacks"] += 1
            continue
            
        is_tp = (pred_is_vuln == True and gt_is_vuln == True)
        is_tn = (pred_is_vuln == False and gt_is_vuln == False)
        is_fp = (pred_is_vuln == True and gt_is_vuln == False)
        is_fn = (pred_is_vuln == False and gt_is_vuln == True)
        
        if is_tp: summary[key]["TP"] += 1
        if is_tn: summary[key]["TN"] += 1
        if is_fp: summary[key]["FP"] += 1
        if is_fn: summary[key]["FN"] += 1
        
        if gt_category not in summary[key]["vuln_classes"]:
            summary[key]["vuln_classes"][gt_category] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
            
        if is_tp: summary[key]["vuln_classes"][gt_category]["TP"] += 1
        if is_tn: summary[key]["vuln_classes"][gt_category]["TN"] += 1
        if is_fp: summary[key]["vuln_classes"][gt_category]["FP"] += 1
        if is_fn: summary[key]["vuln_classes"][gt_category]["FN"] += 1
        
        pred_sev = r.get("severity", "Informational")
        if not pred_is_vuln:
            pred_sev = "Informational"
            
        if pred_sev not in summary[key]["severity_matrix"]:
            summary[key]["severity_matrix"][pred_sev] = {}
        if gt_severity not in summary[key]["severity_matrix"][pred_sev]:
            summary[key]["severity_matrix"][pred_sev][gt_severity] = 0
        summary[key]["severity_matrix"][pred_sev][gt_severity] += 1
        
        conf = r.get("confidence")
        if conf is not None:
            if is_tp or is_tn:
                summary[key]["confidence_correct"].append(conf)
            elif is_fp or is_fn:
                summary[key]["confidence_incorrect"].append(conf)
                
        if pred_is_vuln and not fallback and model != "static":
            scenario = str(r.get("attack_scenario", "")).lower()
            if "an exact exploit path cannot be established" in scenario or scenario == "n/a" or scenario == "none":
                summary[key]["generic"] += 1
            elif "attacker exploits vulnerable pattern" in scenario:
                summary[key]["generic"] += 1
            else:
                summary[key]["partially_grounded"] += 1
                
    for k, v in summary.items():
        tp, tn, fp, fn = v["TP"], v["TN"], v["FP"], v["FN"]
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        mean_conf_correct = sum(v["confidence_correct"]) / len(v["confidence_correct"]) if v["confidence_correct"] else 0
        mean_conf_incorrect = sum(v["confidence_incorrect"]) / len(v["confidence_incorrect"]) if v["confidence_incorrect"] else 0
        
        v["metrics"] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "fpr": fpr,
            "fnr": fnr,
            "mean_conf_correct": mean_conf_correct,
            "mean_conf_incorrect": mean_conf_incorrect
        }
        
    return summary

def main():
    merged_path = "results/raw_merged_results.json"
    if not os.path.exists(merged_path):
        merged_path = "results/raw_evaluation_results.json" # Fallback to original
        
    try:
        with open(merged_path, "r") as f:
            results = json.load(f)
    except FileNotFoundError:
        print("Waiting for raw results...")
        return
        
    with open("ground_truth.json", "r") as f:
        ground_truth = json.load(f)
        
    summary = compute_metrics(results, ground_truth)
    
    with open("results/evaluation_dashboard_data.json", "w") as f:
        json.dump(summary, f, indent=2)
        
if __name__ == "__main__":
    main()
