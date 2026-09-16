import re
with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "r") as f:
    content = f.read()

# I will replace `clean = re.sub(r'//.*$', '', line).strip()` in `_check_reentrancy` with string literal removal
old_reentrancy_clean = r"""
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            # Don't flag .call("") on the previous line if this line is another .call("")
            # Wait, the rule is to find an external call.
            if re.search(r"\.(?:call\s*(?:\{|\()|transfer\s*\(|send\s*\()", clean):
"""

new_reentrancy_clean = r"""
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            # remove string literals
            clean = re.sub(r'".*?"', '""', clean)
            clean = re.sub(r"'.*?'", "''", clean)
            # Don't flag .call("") on the previous line if this line is another .call("")
            # Wait, the rule is to find an external call.
            if re.search(r"\.(?:call\s*(?:\{|\()|transfer\s*\(|send\s*\(|delegatecall\s*\()", clean):
"""
content = content.replace(old_reentrancy_clean, new_reentrancy_clean)
with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "w") as f:
    f.write(content)
