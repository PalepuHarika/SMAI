import re

with open("backend/analyzer/static_analyzer.py", "r", encoding="utf-8") as f:
    content = f.read()

pattern = re.compile(
    r"    def _check_floating_pragma\(self, lines: List\[str\], findings: List\[StaticFinding\]\):.*?(?=    def _check_ecrecover_validation)",
    re.DOTALL
)

match = pattern.search(content)
if not match:
    print("NOT FOUND")
else:
    print("FOUND at", match.start(), match.end())
    start = match.start()
    end = match.end()
    
    # Build new method as a raw string to avoid regex escape issues
    new_method_lines = [
        '    def _check_floating_pragma(self, lines, findings):\n',
        '        """\n',
        '        Detects floating pragma (SWC-103).\n',
        '        Rules:\n',
        '        - pragma solidity 0.8.20   -> PINNED, no finding\n',
        '        - pragma solidity ^0.8.0   -> FLOATING (caret), finding\n',
        '        - pragma solidity ~0.8.0   -> FLOATING (tilde), finding\n',
        '        - pragma solidity >=0.8.0  -> FLOATING (open range), finding\n',
        '        - pragma solidity >=0.8.0 <0.9.0 -> CONSTRAINED, no finding\n',
        '        """\n',
        '        for idx, line in enumerate(lines):\n',
        '            clean = re.sub(r"//.*$", "", line).strip()\n',
        '            if not clean.startswith("pragma solidity"):\n',
        '                continue\n',
        '            vm = re.search(r"pragma\\s+solidity\\s+([^;]+)", clean)\n',
        '            if not vm:\n',
        '                continue\n',
        '            spec = vm.group(1).strip()\n',
        '            # Caret or tilde: always floating\n',
        '            if re.search(r"[\\^~]", spec):\n',
        '                findings.append(StaticFinding(\n',
        '                    id=f"finding-{uuid.uuid4().hex[:8]}",\n',
        '                    contract="Global", function="",\n',
        '                    line_start=idx + 1, line_end=idx + 1,\n',
        '                    category="floating-pragma", confidence=0.95,\n',
        "                    message=(\n",
        '                        f\'Floating Pragma (SWC-103): The pragma "{spec}" allows multiple \'\n',
        "                        f'compiler versions. Pin to an exact version '\n",
        "                        f'(e.g. pragma solidity 0.8.20;) for deterministic compilation.'\n",
        "                    ),\n",
        '                    snippet=clean,\n',
        '                    severity=CATEGORY_SEVERITY_MAP.get("floating-pragma", "Low"),\n',
        '                    swc_id=CATEGORY_SWC_MAP.get("floating-pragma", "SWC-103")\n',
        '                ))\n',
        '                continue\n',
        '            has_lower = bool(re.search(r">", spec))\n',
        '            has_upper = bool(re.search(r"<", spec))\n',
        '            if has_lower and has_upper:\n',
        '                # Closed range e.g. >=0.8.0 <0.9.0 -> constrained, NOT floating pragma\n',
        '                continue\n',
        '            if has_lower and not has_upper:\n',
        '                # Open-ended e.g. >=0.8.0 -> truly floating\n',
        '                findings.append(StaticFinding(\n',
        '                    id=f"finding-{uuid.uuid4().hex[:8]}",\n',
        '                    contract="Global", function="",\n',
        '                    line_start=idx + 1, line_end=idx + 1,\n',
        '                    category="floating-pragma", confidence=0.90,\n',
        "                    message=(\n",
        '                        f\'Floating Pragma (SWC-103): The pragma "{spec}" has no upper \'\n',
        "                        f'version bound. Future compiler versions may introduce breaking '\n",
        "                        f'changes. Use a closed range (e.g. >=0.8.0 <0.9.0) or pin to '\n",
        "                        f'an exact version.'\n",
        "                    ),\n",
        '                    snippet=clean,\n',
        '                    severity=CATEGORY_SEVERITY_MAP.get("floating-pragma", "Low"),\n',
        '                    swc_id=CATEGORY_SWC_MAP.get("floating-pragma", "SWC-103")\n',
        '                ))\n',
        '                continue\n',
        '            # Exact pinned version (e.g. 0.8.20) -> no finding\n',
        '\n',
        '    ',
    ]
    new_method = "".join(new_method_lines)
    
    new_content = content[:start] + new_method + content[end:]
    
    with open("backend/analyzer/static_analyzer.py", "w", encoding="utf-8") as f:
        f.write(new_content)
    print("SUCCESS: method replaced")
    
    with open("backend/analyzer/static_analyzer.py", "r", encoding="utf-8") as f:
        v = f.read()
    print("has_lower and has_upper present:", "has_lower and has_upper" in v)
