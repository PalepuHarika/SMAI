import json
import os

def main():
    merged = []
    
    if os.path.exists("results/raw_evaluation_results.json"):
        with open("results/raw_evaluation_results.json", "r") as f:
            base_results = json.load(f)
            for r in base_results:
                r["dataset"] = "Internal Diagnostic Suite"
                r["prompt"] = "P1" # Main run was P1
                merged.append(r)
                
    if os.path.exists("results/raw_p0_results.json"):
        with open("results/raw_p0_results.json", "r") as f:
            p0_results = json.load(f)
            merged.extend(p0_results)
            
    with open("results/raw_merged_results.json", "w") as f:
        json.dump(merged, f, indent=2)
        
if __name__ == "__main__":
    main()
