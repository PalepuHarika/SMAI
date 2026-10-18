import re

sample_err = """
ParserError: Expected ';' but got 'function'
 --> <stdin>:4:3:
  |
4 |   function f() public {}
  |   ^^^^^^^^
DeclarationError: Undeclared identifier "y".
 --> <stdin>:7:9:
  |
7 |         y = 10;
  |         ^
Warning: SPDX license identifier not provided in source file.
 --> <stdin>
"""

def parse_solc_diagnostics(err_text: str):
    diagnostics = []
    # Pattern to match standard solc diagnostics
    pattern = re.compile(
        r'^(ParserError|DeclarationError|TypeError|SyntaxError|DocstringParsingError|Error|Warning)(?::\s*|\s+)(.*?)\n\s*-->\s*([^:\n]+)(?::(\d+)(?::(\d+))?)?',
        re.MULTILINE
    )
    for m in pattern.finditer(err_text):
        diag_type = m.group(1)
        msg = m.group(2).strip()
        src = m.group(3).strip()
        line = int(m.group(4)) if m.group(4) else 0
        col = int(m.group(5)) if m.group(5) else 0
        is_warning = "warning" in diag_type.lower()
        diagnostics.append({
            "error_type": diag_type,
            "severity": "warning" if is_warning else "error",
            "message": msg,
            "source_location": src,
            "line": line,
            "column": col
        })
    return diagnostics

diags = parse_solc_diagnostics(sample_err)
for d in diags:
    print(d)
