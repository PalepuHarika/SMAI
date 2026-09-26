import re
with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "r") as f:
    content = f.read()

content = content.replace(
    'rest_of_func = " ".join(re.sub(r\'//.*$\', \'\', l).strip() for l in f_lines[idx+1:])',
    'rest_of_func = clean + " " + " ".join(re.sub(r\'//.*$\', \'\', l).strip() for l in f_lines[idx+1:])'
)

with open(r"c:\Users\palep\OneDrive\Desktop\SMAI\backend\analyzer\static_analyzer.py", "w") as f:
    f.write(content)
