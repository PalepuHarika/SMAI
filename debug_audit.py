from tests.expanded_audit_patched import analyzer, CODES
findings = analyzer.analyze(CODES["ReentrancyExpanded.sol"], "ReentrancyExpanded")
for f in findings:
    if f.category == "reentrancy":
        print(f.function)
