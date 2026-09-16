import re
with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "r") as f:
    content = f.read()

# We need to replace the `^\s*(?:require|assert|if)\b` with a better check.
old_code = r"if re.search(r'^\s*(?:require|assert|if)\b', line):"
new_code = r"if re.search(r'\b(?:require|assert|if|return)\s*\([^;]*\b(?:call|delegatecall|send)\b', clean) or re.search(r'\breturn\s+[^;]*\b(?:call|delegatecall|send)\b', clean):"

content = content.replace(old_code, new_code)

with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "w") as f:
    f.write(content)
