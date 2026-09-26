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
                # Need to make sure it's actually in a require/if/assert
                if re.search(r'\b(?:require|assert|if)\s*\(', clean):
                    return True
"""
content = content.replace(old_auth_check, new_auth_check)

# And wait! What about internal helper calls?
# test9() public { _auth(); selfdestruct(owner); }
# We need to trace internal calls too, but I don't want to build a full AST.
# I can just iterate through f_lines and see if they call a function that has auth.
helper_check = r"""
        if functions and all_lines:
            header_words = set(re.findall(r'\b[a-zA-Z0-9_]+\b', f_header))
            for func in functions:
                if func.get('type') == 'modifier' and func['name'] in header_words:
                    m_lines = all_lines[func['start'] - 1 : func['end']]
                    if self._has_valid_caller_authorization(all_lines[func['start'] - 1], m_lines):
                        return True
            
            # check internal helper calls
            for line in f_lines:
                clean = re.sub(r'//.*$', '', line).strip()
                matches = re.findall(r'\b([a-zA-Z0-9_]+)\s*\(', clean)
                for called_func in matches:
                    for func in functions:
                        if func.get('type') == 'function' and func['name'] == called_func and func['name'] != f_header.split()[1].split('(')[0]:
                            m_lines = all_lines[func['start'] - 1 : func['end']]
                            if self._has_valid_caller_authorization(all_lines[func['start'] - 1], m_lines):
                                return True
"""
content = re.sub(r'        if functions and all_lines:.*?return True\n', helper_check, content, flags=re.DOTALL)

with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "w") as f:
    f.write(content)
