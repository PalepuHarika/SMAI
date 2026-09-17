from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

contracts = {
    "SafeVault": "contracts/CleanSafeVault.sol",
    "Reentrancy": "contracts/ReentrancyVault.sol",
    "MultiVulnerable": "contracts/test_suite/TC11_Combined.sol"
}

analyzer = SolidityStaticAnalyzer()

for name, path in contracts.items():
    print(f"--- {name} ---")
    with open(path, "r") as f:
        code = f.read()
    raw_findings = analyzer.analyze(code, name)
    if not raw_findings:
        print("No static findings.")
    for f in raw_findings:
        print(f"Category: {f.category} | SWC: {f.swc_id} | Severity: {f.severity} | Conf: {f.confidence}")
