import re
clean = 'function test2(address target) public { (bool ok, ) = target.call(""); require(ok); }'
clean2 = 'bool ok = target.call("");'

for c in [clean, clean2]:
    m = re.search(r'([^;={}]*)=\s*[^;=]*\.\s*(?:call|delegatecall|send)\b', c)
    if m:
        lhs = m.group(1).strip()
        print("LHS:", lhs)
        # extract the first word that looks like a variable
        # remove (bool, or (
        clean_lhs = re.sub(r'\(?\s*(?:bool\s+)?', '', lhs)
        var_name = clean_lhs.split(',')[0].strip()
        print("VAR:", var_name)
