import re
with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "r") as f:
    content = f.read()

old_auth_check = r"""
        # 2. Check function body for caller authorization checks
        for line in f_lines:
            clean = re.sub(r'//.*$', '', line).strip()
            if clean.startswith('require') or clean.startswith('assert') or clean.startswith('if'):
                is_caller_check = bool(
                    re.search(r'\bmsg\.sender\s*(?:==|!=)\s*[a-zA-Z0-9_\.]+', clean) or
                    re.search(r'[a-zA-Z0-9_\.]+\s*(?:==|!=)\s*msg\.sender\b', clean) or
                    re.search(r'\bhasRole\s*\([^)]*msg\.sender[^)]*\)', clean) or
                    re.search(r'\bisOwner\s*\([^)]*msg\.sender[^)]*\)', clean) or
                    re.search(r'\bcheckRole\s*\([^)]*msg\.sender[^)]*\)', clean)
                )
                if is_caller_check:
                    return True
"""

new_auth_check = r"""
        # 2. Check function body for caller authorization checks
        for line in f_lines:
            clean = re.sub(r'//.*$', '', line).strip()
            # If the line contains an authorization check anywhere
            is_caller_check = bool(
                re.search(r'\bmsg\.sender\s*(?:==|!=)\s*[a-zA-Z0-9_\.]+', clean) or
                re.search(r'[a-zA-Z0-9_\.]+\s*(?:==|!=)\s*msg\.sender\b', clean) or
                re.search(r'\bhasRole\s*\([^)]*msg\.sender[^)]*\)', clean) or
                re.search(r'\bisOwner\s*\([^)]*msg\.sender[^)]*\)', clean) or
                re.search(r'\bcheckRole\s*\([^)]*msg\.sender[^)]*\)', clean) or
                re.search(r'\btx\.origin\s*(?:==|!=)\s*[a-zA-Z0-9_\.]+', clean) or
                re.search(r'[a-zA-Z0-9_\.]+\s*(?:==|!=)\s*tx\.origin\b', clean)
            )
            if is_caller_check:
                if re.search(r'\b(?:require|assert|if)\s*\(', clean):
                    return True
"""
if old_auth_check in content:
    content = content.replace(old_auth_check, new_auth_check)
    with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "w") as f:
        f.write(content)
else:
    print("Old auth check not found")
