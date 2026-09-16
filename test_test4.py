import re
clean = 'function test4(address target) public { bool ok = target.call(""); if (ok) {} }'
m = re.search(r'([^;={}]*)=\s*[^;=]*\.\s*(?:call|delegatecall|send)\b', clean)
var_name = re.sub(r'\(?\s*(?:bool\s+)?', '', m.group(1).strip()).split(',')[0].strip()
print("VAR:", var_name)
rest_of_func = clean
match = re.search(rf'\b(?:require|assert|if)\s*\([^)]*\b{var_name}\b', rest_of_func)
print("MATCH:", bool(match))
