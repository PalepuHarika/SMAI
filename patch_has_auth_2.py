import re
with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "r") as f:
    content = f.read()

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
                        if func.get('type') == 'function' and func['name'] == called_func:
                            m_lines = all_lines[func['start'] - 1 : func['end']]
                            if self._has_valid_caller_authorization(all_lines[func['start'] - 1], m_lines):
                                return True
"""
content = re.sub(r'        if functions and all_lines:.*?return True\n', lambda m: helper_check, content, flags=re.DOTALL)

with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "w") as f:
    f.write(content)
