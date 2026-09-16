import re
clean = 'function test2(address target) public { (bool ok, ) = target.call(""); require(ok); }'
m = re.search(r'(?:bool\s+)?\(?\s*(?:bool\s+)?([a-zA-Z0-9_]+)\b[^=]*=\s*[^;=]*\.\s*(?:call|delegatecall|send)\b', clean)
print(m.group(1) if m else "None")

clean2 = 'bool ok = target.call("");'
m2 = re.search(r'(?:bool\s+)?\(?\s*(?:bool\s+)?([a-zA-Z0-9_]+)\b[^=]*=\s*[^;=]*\.\s*(?:call|delegatecall|send)\b', clean2)
print(m2.group(1) if m2 else "None")
