from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

analyzer = SolidityStaticAnalyzer()

cases = [
    ("empty", ""),
    ("comments-only", "// just a comment\n/* block */"),
    ("strings-only", 'contract A { string a = "contract B {} function C()"; }'),
    ("malformed", "contract { function } } { { msg.sender.call() }"),
    ("truncated", "contract A { function b() public { msg.sender.call("),
    ("unicode", "contract A { // \u2603\n }")
]

for name, code in cases:
    try:
        analyzer.analyze(code, name)
        print(f"Robustness {name}: PASS")
    except Exception as e:
        print(f"Robustness {name}: FAIL {e}")
