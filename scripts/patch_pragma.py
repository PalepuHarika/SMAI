import re

with open("backend/analyzer/static_analyzer.py", "r", encoding="utf-8") as f:
    content = f.read()

NEW_METHOD = """    def _check_floating_pragma(self, lines, findings):
        for idx, line in enumerate(lines):
            clean = re.sub(r"//.*$", "", line).strip()
            if not clean.startswith("pragma solidity"):
                continue
            vm = re.search(r"pragma\\s+solidity\\s+([^;]+)", clean)
            if not vm:
                continue
            spec = vm.group(1).strip()
            if re.search(r"[\\^~]", spec):
                findings.append(StaticFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    contract="Global", function="",
                    line_start=idx + 1, line_end=idx + 1,
                    category="floating-pragma", confidence=0.95,
                    message=(
                        f'Floating Pragma (SWC-103): The pragma "{spec}" allows multiple compiler '
                        f'versions. Pin to an exact version (e.g. pragma solidity 0.8.20;) '
                        f'for deterministic compilation.'
                    ),
                    snippet=clean,
                    severity=CATEGORY_SEVERITY_MAP.get("floating-pragma", "Low"),
                    swc_id=CATEGORY_SWC_MAP.get("floating-pragma", "SWC-103")
                ))
                continue
            has_lower = bool(re.search(r">", spec))
            has_upper = bool(re.search(r"<", spec))
            if has_lower and has_upper:
                continue
            if has_lower and not has_upper:
                findings.append(StaticFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    contract="Global", function="",
                    line_start=idx + 1, line_end=idx + 1,
                    category="floating-pragma", confidence=0.90,
                    message=(
                        f'Floating Pragma (SWC-103): The pragma "{spec}" has no upper version '
                        f'bound. Future compiler versions may introduce breaking changes. '
                        f'Use a closed range (e.g. >=0.8.0 <0.9.0) or pin to an exact version.'
                    ),
                    snippet=clean,
                    severity=CATEGORY_SEVERITY_MAP.get("floating-pragma", "Low"),
                    swc_id=CATEGORY_SWC_MAP.get("floating-pragma", "SWC-103")
                ))
                continue

"""

pattern = re.compile(
    r"    def _check_floating_pragma\\(self, lines: List\\[str\\], findings: List\\[StaticFinding\\]\\):.*?(?=    def _check_ecrecover_validation)",
    re.DOTALL
)

new_content = pattern.sub(NEW_METHOD, content)

if new_content == content:
    print("ERROR: No replacement made!")
else:
    with open("backend/analyzer/static_analyzer.py", "w", encoding="utf-8") as f:
        f.write(new_content)
    print("SUCCESS")
