import json

def main():
    try:
        with open("test_suite_results.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("test_suite_results.json not found")
        return
        
    md = "# Genuine LLM Evaluation Report (7B Model)\n\n"
    
    total_calls = 0
    successful_calls = 0
    failed_calls = 0
    fallback_count = 0
    validation_failures = 0
    correct_decisions = 0
    incorrect_decisions = 0
    models_used = set()
    
    # Ground truth mapping for the 8-contract baseline
    # (Contract Name) -> Should the LLM flag it as Vulnerable?
    ground_truth = {
        "TC1_TxOriginAuth.sol": True,
        "TC3_ReentrancyVault.sol": True,
        "TC4_DangerousDelegatecall.sol": True,
        "TC13_Decoy.sol": False, # String decoy
        "TC8_TxOriginFalsePositive.sol": False, # Event log only
        "TC14_MultiFunction.sol": True,
        "TC15_Hallucination.sol": True,
        "TC12_CleanContract.sol": False # Analyzer finds 0, so LLM not called
    }
    
    fp_total = 0
    fp_rejected = 0
    
    md += "## Individual Contract Results\n\n"
    
    for test, result in data.items():
        if "error" in result:
            md += f"### {test}\n- **Error:** {result['error']}\n\n"
            continue
            
        md += f"### {test}\n"
        md += f"- **Is Vulnerable (System):** {result['is_vulnerable']}\n"
        md += f"- **Total Findings:** {result['total_findings']}\n\n"
        
        expected_vulnerable = ground_truth.get(test, True)
        
        if result['total_findings'] == 0:
            md += "*(No static findings - LLM was skipped)*\n\n"
            continue
            
        for i, f in enumerate(result['findings']):
            total_calls += 1
            fallback_used = f.get('fallback_used', False)
            model_used = f.get('model_used', 'unknown')
            models_used.add(model_used)
            
            if fallback_used:
                fallback_count += 1
                failed_calls += 1
                if "JSON Parsing or Pydantic Validation Error" in f.get('fallback_reason', ''):
                    validation_failures += 1
            else:
                successful_calls += 1
                
                # Check correctness
                llm_decision = f.get('is_vulnerable', True)
                if llm_decision == expected_vulnerable:
                    correct_decisions += 1
                else:
                    incorrect_decisions += 1
                    
                # Track False Positive rejections (TC13, TC8)
                if not expected_vulnerable:
                    fp_total += 1
                    if not llm_decision:
                        fp_rejected += 1

            md += f"#### Finding {i+1}\n"
            md += f"- **Model Used:** {model_used}\n"
            md += f"- **Inference Success:** {'FAIL' if fallback_used else 'SUCCESS'}\n"
            md += f"- **Fallback Used:** {fallback_used}\n"
            md += f"- **Fallback Reason:** {f.get('fallback_reason', 'N/A')}\n"
            md += f"- **LLM is_vulnerable Output:** {f.get('is_vulnerable')}\n"
            md += f"- **Expected is_vulnerable:** {expected_vulnerable}\n"
            md += f"- **Raw Response:**\n```json\n{f.get('raw_response', 'N/A')}\n```\n"
            md += f"- **Category:** {f.get('vulnerability')}\n"
            md += f"- **Severity:** {f.get('severity')}\n"
            md += f"- **Grounded Evidence:** {f.get('evidence')}\n"
            md += f"- **Attack Scenario:** {f.get('attack_scenario')}\n\n"
            
    # Metrics Summary
    md_metrics = "## Metrics Summary\n\n"
    md_metrics += f"- **Actual Model Used:** {', '.join(models_used) if models_used else 'None'}\n"
    md_metrics += f"- **LLM Calls Attempted:** {total_calls}\n"
    md_metrics += f"- **Successful LLM Calls:** {successful_calls}\n"
    md_metrics += f"- **Failed LLM Calls:** {failed_calls}\n"
    md_metrics += f"- **Fallback Count:** {fallback_count}\n"
    md_metrics += f"- **Raw-Response Validation Failures:** {validation_failures}\n"
    md_metrics += f"- **Correct LLM Decisions:** {correct_decisions}\n"
    md_metrics += f"- **Incorrect LLM Decisions:** {incorrect_decisions}\n"
    
    fp_rate = f"{(fp_rejected/fp_total)*100:.1f}% ({fp_rejected}/{fp_total})" if fp_total > 0 else "N/A"
    md_metrics += f"- **False-Positive Rejection Rate:** {fp_rate}\n"
    md_metrics += f"- **Grounding Quality:** Evaluated below based on evidence/scenarios.\n"
    
    with open("llm_baseline_report.md", "w") as f:
        f.write(md_metrics + "\n" + md)
        
    print("Generated llm_baseline_report.md")

if __name__ == "__main__":
    main()
