import re
with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "r") as f:
    content = f.read()

# We need to replace the entire block for capture_match:
old_code = re.compile(r"capture_match = re\.search\(r'\^\\s\*\(\?:bool\\s\+\)\?\\\?\\s\*\(\?:bool\\s\+\)\?\(\[a-zA-Z0-9_\]\+\)\\b\[\^=\]\*=', clean\)\n\s*if capture_match:\n\s*var_name = capture_match\.group\(1\)\n\s*is_checked = False\n\s*rest_of_func = clean \+ \" \" \+ \" \"\.join\(re\.sub\(r'//\.\*\$', '', l\)\.strip\(\) for l in f_lines\[idx\+1:\]\)\n\s*if re\.search\(rf'\\b\(\?:require\|assert\|if\)\\s\*\\\(\[\^\)\]\*\\b\{var_name\}\\b', rest_of_func\):", re.DOTALL)

new_code = r"""
            capture_match = re.search(r'([^;={}]*)=\s*[^;=]*\.\s*(?:call|delegatecall|send)\b', clean)
            if capture_match:
                lhs = capture_match.group(1).strip()
                clean_lhs = re.sub(r'\(?\s*(?:bool\s+)?', '', lhs)
                var_name = clean_lhs.split(',')[0].strip()
                # If the variable is empty (e.g. (, bytes data) = target.call), we can't check it, so it remains unchecked
                if var_name:
                    is_checked = False
                    rest_of_func = clean + " " + " ".join(re.sub(r'//.*$', '', l).strip() for l in f_lines[idx+1:])
                    if re.search(rf'\b(?:require|assert|if)\s*\([^)]*\b{var_name}\b', rest_of_func):
"""
# wait, what if `var_name` has spaces or is something else? `re.match(r'^[a-zA-Z0-9_]+', var_name)`
new_code2 = r"""
            capture_match = re.search(r'([^;={}]*)=\s*[^;=]*\.\s*(?:call|delegatecall|send)\b', clean)
            if capture_match:
                lhs = capture_match.group(1).strip()
                clean_lhs = re.sub(r'\(?\s*(?:bool\s+)?', '', lhs)
                var_name = clean_lhs.split(',')[0].strip()
                
                is_checked = False
                rest_of_func = clean + " " + " ".join(re.sub(r'//.*$', '', l).strip() for l in f_lines[idx+1:])
                if var_name and re.search(rf'\b(?:require|assert|if)\s*\([^)]*\b{var_name}\b', rest_of_func):
"""

content = old_code.sub(lambda m: new_code2.strip('\n'), content)

with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "w") as f:
    f.write(content)
