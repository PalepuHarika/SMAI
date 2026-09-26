import sys
sys.path.insert(0, '.')
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

code = open('tests/test_multiple_findings.py').read().split('"""')[1]
print("Code being analyzed:\n", code)
findings = SolidityStaticAnalyzer().analyze(code, 'MultiBug.sol')
print(f"Total static findings: {len(findings)}")
for f in findings:
    print(f"Finding: {f.category} | SWC: {f.swc_id} | Func: {f.function} | Lines: {f.line_start}-{f.line_end}")
