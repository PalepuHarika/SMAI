with open("backend/analyzer/static_analyzer.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix the indentation issue: replace the nested def back to class method level
old = "        # Exact pinned version (e.g. 0.8.20) -> no finding\n\n        def _check_ecrecover_validation"
new = "        # Exact pinned version (e.g. 0.8.20) -> no finding\n\n    def _check_ecrecover_validation"

if old in content:
    content = content.replace(old, new, 1)
    with open("backend/analyzer/static_analyzer.py", "w", encoding="utf-8") as f:
        f.write(content)
    print("Fixed indentation")
else:
    print("Pattern not found, trying alternative...")
    # Try with different whitespace
    import re
    content2 = re.sub(
        r'(        # Exact pinned version \(e\.g\. 0\.8\.20\) -> no finding\n\n        )(def _check_ecrecover_validation)',
        r'\g<1>'[:-8] + '    ' + r'\g<2>',
        content
    )
    if content2 != content:
        with open("backend/analyzer/static_analyzer.py", "w", encoding="utf-8") as f:
            f.write(content2)
        print("Fixed via regex")
    else:
        # Find the exact text
        idx = content.find("# Exact pinned version")
        print("Context around pinned version:", repr(content[idx:idx+200]))
