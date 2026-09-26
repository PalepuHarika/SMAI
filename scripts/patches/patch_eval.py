import re
with open("tests/expanded_audit.py", "r") as f:
    content = f.read()

# I will systematically replace all `(False, None)` with the category of that contract.
# Let's do it with regex.
def replace_none(content, contract_name, cat):
    # Find the EXPECTED[contract_name] block
    block_re = re.compile(rf'EXPECTED\["{contract_name}"\] = {{(.*?)}}', re.DOTALL)
    m = block_re.search(content)
    if m:
        block = m.group(1)
        new_block = block.replace('(False, None)', f'(False, "{cat}")')
        content = content[:m.start(1)] + new_block + content[m.end(1):]
    return content

content = replace_none(content, "ReentrancyExpanded.sol", "reentrancy")
content = replace_none(content, "UncheckedExpanded.sol", "unchecked-call")
content = replace_none(content, "TxOriginExpanded.sol", "tx-origin")
content = replace_none(content, "TimestampExpanded.sol", "timestamp-dependence")
content = replace_none(content, "SelfdestructExpanded.sol", "unprotected-selfdestruct")
content = replace_none(content, "DelegatecallExpanded.sol", "dangerous-delegatecall")
content = replace_none(content, "ZeroAddressExpanded.sol", "missing-zero-check")
content = replace_none(content, "AccessControlExpanded.sol", "missing-access-control")
content = replace_none(content, "FloatingPragma2.sol", "floating-pragma")
content = replace_none(content, "EcrecoverExpanded.sol", "ecrecover-validation")
content = replace_none(content, "OverflowExpanded8.sol", "integer-overflow")

# In the evaluation loop, we check expected_cat:
eval_logic = r"""
        if expect_detect:
            if expected_cat in found_cats:
                stats["passed"] += 1
                cat_metrics[expected_cat]["TP"] += 1
                results_table.append(f"{expected_cat:25} | {func:20} | True  | True  | PASS | -")
            else:
                stats["failed"] += 1
                stats["fn"] += 1
                cat_metrics[expected_cat]["FN"] += 1
                results_table.append(f"{expected_cat:25} | {func:20} | True  | False | FAIL | FALSE NEGATIVE")
        else:
            if expected_cat in found_cats:
                stats["failed"] += 1
                stats["fp"] += 1
                cat_metrics[expected_cat]["FP"] += 1
                results_table.append(f"{expected_cat:25} | {func:20} | False | True  | FAIL | FALSE POSITIVE")
            else:
                stats["passed"] += 1
                if expected_cat and expected_cat != "unknown":
                    cat_metrics[expected_cat]["TN"] += 1
                results_table.append(f"{expected_cat:25} | {func:20} | False | False | PASS | -")
"""

content = re.sub(r'\n\s*if expect_detect:.*?\n\s*results_table\.append\(f"\{cat:25\} \| \{func:20\} \| False \| False \| PASS \| -"\)', eval_logic, content, flags=re.DOTALL)

with open("tests/expanded_audit_patched.py", "w") as f:
    f.write(content)
