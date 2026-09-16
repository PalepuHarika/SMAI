import re
import uuid
from typing import List, Dict, Any, Tuple, Optional
from backend.core.finding import StaticFinding

CATEGORY_SEVERITY_MAP = {
    "dangerous-delegatecall": "Critical",
    "unprotected-selfdestruct": "Critical",
    "reentrancy": "High",
    "tx-origin": "High",
    "missing-access-control": "High",
    "unchecked-call": "Medium",
    "timestamp-dependence": "Medium",
    "uninitialized-storage": "Medium",
    "missing-zero-check": "Low",
    "floating-pragma": "Low",
    "ecrecover-validation": "High",
    "integer-overflow": "High",
}

CATEGORY_SWC_MAP = {
    "reentrancy": "SWC-107",
    "unchecked-call": "SWC-104",
    "tx-origin": "SWC-115",
    "timestamp-dependence": "SWC-116",
    "unprotected-selfdestruct": "SWC-106",
    "dangerous-delegatecall": "SWC-112",
    "uninitialized-storage": "SWC-109",
    "missing-zero-check": "SWC-136",
    "floating-pragma": "SWC-103",
    "ecrecover-validation": "SWC-117",
    "integer-overflow": "SWC-101",
    "missing-access-control": "SWC-105",
}

class SolidityStaticAnalyzer:
    """
    Solidity static analysis engine that extracts contract structures
    and flags suspicious security patterns based on AST and heuristic rules.
    """

    def __init__(self):
        self.contract_pattern = re.compile(r'\b(?:contract|library|interface)\s+([a-zA-Z0-9_]+)', re.MULTILINE)
        self.func_pattern = re.compile(r'\b(?:function\s+([a-zA-Z0-9_]+)|modifier\s+([a-zA-Z0-9_]+)|constructor\s*\(|fallback\s*\(|receive\s*\()', re.MULTILINE)

    def analyze(self, source_code: str, contract_name: Optional[str] = None) -> List[StaticFinding]:
        if not source_code or not source_code.strip():
            return []

        lines = source_code.splitlines()
        findings: List[StaticFinding] = []
        
        self._check_floating_pragma(lines, findings)

        contracts = self._parse_contracts(lines)
        if not contracts:
            contracts = [{
                'name': contract_name or 'MainContract',
                'start': 1,
                'end': len(lines),
                'functions': self._parse_functions(lines, 1, len(lines))
            }]

        for contract in contracts:
            c_name = contract['name']
            c_start = contract['start']
            c_end = contract['end']
            functions = contract['functions']

            self._check_tx_origin(lines, c_name, c_start, c_end, functions, findings)
            self._check_timestamp_dependence(lines, c_name, c_start, c_end, functions, findings)
            self._check_unprotected_selfdestruct(lines, c_name, functions, findings)

            for func in functions:
                f_name = func['name']
                f_start = func['start']
                f_end = func['end']
                f_lines = lines[f_start - 1 : f_end]

                self._check_reentrancy(f_lines, c_name, f_name, f_start, findings, lines, functions)
                self._check_unchecked_calls(f_lines, c_name, f_name, f_start, findings)
                self._check_dangerous_delegatecall(f_lines, c_name, f_name, f_start, findings, lines)
                self._check_uninitialized_storage_pointers(f_lines, c_name, f_name, f_start, findings)
                self._check_missing_zero_address_validation(f_lines, c_name, f_name, f_start, findings, lines)
                self._check_missing_access_control(f_lines, c_name, f_name, f_start, findings, lines, functions)
                self._check_ecrecover_validation(f_lines, c_name, f_name, f_start, findings)
                self._check_integer_overflow(lines, f_lines, c_name, f_name, f_start, findings)

        return findings

    def _is_state_write(self, clean_line: str) -> bool:
        if clean_line.startswith('require') or clean_line.startswith('if') or clean_line.startswith('emit') or \
           clean_line.startswith('assert') or clean_line.startswith('revert') or clean_line.startswith('return'):
            return False
            
        if not re.search(r'(=|\+=|-=|\*=|/=|%=|\+\+|--|\.push\(|\.pop\()', clean_line):
            return False
            
        local_decl_pattern = r'^\s*(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping|var|let|[A-Z][a-zA-Z0-9_]*)\s+(?:payable\s+|memory\s+|storage\s+|calldata\s+)?(?:\[\]\s*)?[a-zA-Z0-9_]+\s*='
        if re.search(local_decl_pattern, clean_line):
            return False
            
        if re.search(r'^\s*\(', clean_line):
            return False
            
        return True
    def _parse_contracts(self, lines: List[str]) -> List[Dict[str, Any]]:
        contracts = []
        i = 0
        while i < len(lines):
            line = lines[i]
            match = re.search(r'\b(?:contract|library|interface)\s+([a-zA-Z0-9_]+)', line)
            if match:
                c_name = match.group(1)
                c_start = i + 1
                c_end = self._find_closing_brace(lines, i)
                functions = self._parse_functions(lines, c_start, c_end)
                contracts.append({
                    'name': c_name,
                    'start': c_start,
                    'end': c_end,
                    'functions': functions
                })
                i = c_end
            else:
                i += 1
        return contracts

    def _parse_functions(self, lines: List[str], start_line: int, end_line: int) -> List[Dict[str, Any]]:
        functions = []
        i = start_line - 1
        while i < end_line and i < len(lines):
            line = lines[i]
            match = re.search(r'\b(?:function\s+([a-zA-Z0-9_]+)|modifier\s+([a-zA-Z0-9_]+)|constructor\s*\(|fallback\s*\(|receive\s*\()', line)
            if match:
                func_type = 'function'
                if match.group(1):
                    f_name = match.group(1)
                elif match.group(2):
                    f_name = match.group(2)
                    func_type = 'modifier'
                elif 'constructor' in line:
                    f_name = 'constructor'
                elif 'receive' in line:
                    f_name = 'receive'
                else:
                    f_name = 'fallback'

                f_start = i + 1
                f_end = self._find_closing_brace(lines, i)
                functions.append({
                    'name': f_name,
                    'type': func_type,
                    'start': f_start,
                    'end': f_end
                })
                i = f_end
            else:
                i += 1
        return functions

    def _find_closing_brace(self, lines: List[str], start_idx: int) -> int:
        full_text = "\n".join(lines)
        masked_text = []
        i = 0
        in_string = False
        string_char = ''
        in_block_comment = False
        in_line_comment = False
        
        while i < len(full_text):
            c = full_text[i]
            if in_line_comment:
                if c == '\n':
                    in_line_comment = False
                    masked_text.append(c)
                else:
                    masked_text.append(' ')
                i += 1
                continue
                
            if in_block_comment:
                if c == '*' and i + 1 < len(full_text) and full_text[i+1] == '/':
                    in_block_comment = False
                    masked_text.extend([' ', ' '])
                    i += 2
                else:
                    masked_text.append('\n' if c == '\n' else ' ')
                    i += 1
                continue
                
            if in_string:
                if c == '\\' and i + 1 < len(full_text):
                    masked_text.extend([' ', ' '])
                    i += 2
                    continue
                if c == string_char:
                    in_string = False
                    masked_text.append(' ')
                else:
                    masked_text.append('\n' if c == '\n' else ' ')
                i += 1
                continue
                
            if c == '/' and i + 1 < len(full_text):
                if full_text[i+1] == '/':
                    in_line_comment = True
                    masked_text.extend([' ', ' '])
                    i += 2
                    continue
                if full_text[i+1] == '*':
                    in_block_comment = True
                    masked_text.extend([' ', ' '])
                    i += 2
                    continue
                    
            if c == '"' or c == "'":
                in_string = True
                string_char = c
                masked_text.append(' ')
                i += 1
                continue
                
            masked_text.append(c)
            i += 1
            
        masked_lines = "".join(masked_text).split('\n')
        
        brace_count = 0
        found_first = False
        for idx in range(start_idx, len(masked_lines)):
            line = masked_lines[idx]
            for ch in line:
                if ch == '{':
                    brace_count += 1
                    found_first = True
                elif ch == '}':
                    brace_count -= 1
                    if found_first and brace_count == 0:
                        return idx + 1
        return len(lines)

    def _find_enclosing_function(self, line_no: int, functions: List[Dict[str, Any]]) -> str:
        for func in functions:
            if func['start'] <= line_no <= func['end']:
                return func['name']
        return 'contract_scope'

    def _check_reentrancy(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding], all_lines: List[str] = None, functions: List[Dict[str, Any]] = None):
        header = f_lines[0] if f_lines else ""
        
        # Check custom modifiers like nonReentrant
        if re.search(r'\b(nonReentrant|reentrancyGuard)\b', header, re.IGNORECASE):
            return
            
        header_words = set(re.findall(r'\b[a-zA-Z0-9_]+\b', header))
        if 'nonReentrant' in header_words or 'reentrancyGuard' in header_words:
            return

        if functions and all_lines:
            for func in functions:
                if func.get('type') == 'modifier' and func['name'] in header_words:
                    m_lines = all_lines[func['start'] - 1 : func['end']]
                    m_body = " ".join(re.sub(r'//.*$', '', l).strip() for l in m_lines)
                    # Check for simple mutex pattern: require(!locked); locked=true; _; locked=false;
                    if re.search(r'(?:require|if)\s*\([^)]*\)\s*;\s*(?:revert\s*\([^)]*\)\s*;)?\s*[a-zA-Z0-9_.]+\s*=\s*true\s*;\s*_\s*;', m_body):
                        return

        call_line_idx = -1
        call_snippet = ""

        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            # remove string literals
            clean = re.sub(r'".*?"', '""', clean)
            clean = re.sub(r"'.*?'", "''", clean)
            # Don't flag .call("") on the previous line if this line is another .call("")
            # Wait, the rule is to find an external call.
            if re.search(r"\.(?:call\s*(?:\{|\()|transfer\s*\(|send\s*\(|delegatecall\s*\()", clean):
                call_line_idx = idx
                call_snippet = clean
                break

        if call_line_idx != -1:
            for post_idx in range(call_line_idx + 1, len(f_lines)):
                post_line = re.sub(r'//.*$', '', f_lines[post_idx]).strip()
                if not post_line: continue
                
                is_assignment = self._is_state_write(post_line)
                
                # Check if it calls a helper that mutates state
                is_helper_mutation = False
                call_match = re.search(r'^\s*([a-zA-Z0-9_]+)\s*\(', post_line)
                if not is_assignment and call_match and all_lines and functions:
                    helper_name = call_match.group(1)
                    # Exclude builtins
                    if helper_name not in ['require', 'assert', 'revert', 'if', 'emit', 'return']:
                        # Find the helper and see if it has state writes
                        for h_func in functions:
                            if h_func['name'] == helper_name:
                                h_lines = all_lines[h_func['start']-1 : h_func['end']]
                                for h_line in h_lines:
                                    if self._is_state_write(re.sub(r'//.*$', '', h_line).strip()):
                                        is_helper_mutation = True
                                        break
                                break

                if (is_assignment or is_helper_mutation) and \
                   not post_line.startswith('require') and not post_line.startswith('if') and not post_line.startswith('emit') and not post_line.startswith('assert') and not post_line.startswith('revert') and not post_line.startswith('return'):
                    findings.append(StaticFinding(
                        id=f'finding-{uuid.uuid4().hex[:8]}',
                        contract=c_name,
                        function=f_name,
                        line_start=offset + call_line_idx,
                        line_end=offset + post_idx,
                        category='reentrancy',
                        confidence=0.88,
                        message=f'Potential Reentrancy Candidate (SWC-107): External call at line {offset + call_line_idx} occurs before state variable modification at line {offset + post_idx}.',
                        snippet=f'External Call: {call_snippet} | State modification: {post_line}',
                        severity=CATEGORY_SEVERITY_MAP.get('reentrancy', 'High'),
                        swc_id=CATEGORY_SWC_MAP.get('reentrancy', 'SWC-107')
                    ))
                    break

    def _check_unchecked_calls(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            call_match = re.search(r'\b[a-zA-Z0-9_]+\s*\.\s*(call|delegatecall|send)\b', clean)
            if not call_match or clean.startswith('//'):
                continue

            if re.search(r'\b(?:require|assert|if|return)\s*\([^;]*\b(?:call|delegatecall|send)\b', clean) or re.search(r'\breturn\s+[^;]*\b(?:call|delegatecall|send)\b', clean):
                continue

            capture_match = re.search(r'([^;={}]*)=\s*[^;=]*\.\s*(?:call|delegatecall|send)\b', clean)
            if capture_match:
                lhs = capture_match.group(1).strip()
                clean_lhs = re.sub(r'\(?\s*(?:bool\s+)?', '', lhs)
                var_name = clean_lhs.split(',')[0].strip()
                
                is_checked = False
                rest_of_func = clean + " " + " ".join(re.sub(r'//.*$', '', l).strip() for l in f_lines[idx+1:])
                if var_name and re.search(rf'\b(?:require|assert|if)\s*\([^)]*\b{var_name}\b', rest_of_func):
                    is_checked = True
                if is_checked:
                    continue

            findings.append(StaticFinding(
                id=f'finding-{uuid.uuid4().hex[:8]}',
                contract=c_name,
                function=f_name,
                line_start=offset + idx,
                line_end=offset + idx,
                category='unchecked-call',
                confidence=0.85,
                message='Unchecked Low-Level Call (SWC-104): The return value of low-level external call is not checked.',
                snippet=clean,
                severity=CATEGORY_SEVERITY_MAP.get('unchecked-call', 'Medium'),
                swc_id=CATEGORY_SWC_MAP.get('unchecked-call', 'SWC-104')
            ))

    def _check_tx_origin(self, lines: List[str], c_name: str, start: int, end: int, functions: List[Dict[str, Any]], findings: List[StaticFinding]):
        for func in functions:
            f_start = func['start']
            f_end = func['end']
            
            t_vars = {}
            for idx in range(f_start - 1, f_end):
                line = lines[idx]
                clean = re.sub(r'//.*$', '', line).strip()
                assign_match = re.search(r'\b(?:address\s+)?([a-zA-Z0-9_]+)\s*=\s*tx\.origin\b', clean)
                if assign_match:
                    t_vars[assign_match.group(1)] = idx + 1
                    
            f_body = " ".join(re.sub(r'//.*$', '', lines[i]).strip() for i in range(f_start - 1, f_end))
            
            # Modifier check
            f_header = lines[f_start - 1]
            header_words = set(re.findall(r'\b[a-zA-Z0-9_]+\b', f_header))
            for h_func in functions:
                if h_func.get('type') == 'modifier' and h_func['name'] in header_words:
                    m_lines = lines[h_func['start']-1 : h_func['end']]
                    m_body = " ".join(re.sub(r'//.*$', '', l).strip() for l in m_lines)
                    if re.search(r'\b(?:require|assert|if)\s*\([^;]*\btx\.origin\b\s*(?:==|!=)', m_body) or \
                       re.search(r'\b(?:require|assert|if)\s*\([^;]*(?:==|!=)\s*\btx\.origin\b', m_body):
                        findings.append(StaticFinding(
                            id=f'finding-{uuid.uuid4().hex[:8]}',
                            contract=c_name,
                            function=func['name'],
                            line_start=f_start,
                            line_end=f_start,
                            category='tx-origin',
                            confidence=0.88,
                            message='tx.origin used for authorization in modifier (SWC-115)',
                            snippet=f_header.strip(),
                            severity=CATEGORY_SEVERITY_MAP.get('tx-origin', 'High'),
                            swc_id=CATEGORY_SWC_MAP.get('tx-origin', 'SWC-115')
                        ))
                        break
            
            aliases = ['tx.origin'] + list(t_vars.keys())
            
            reported_this_func = False
            for alias in aliases:
                if re.search(rf'\b(?:require|assert|if)\s*\([^;]*\b{alias}\b\s*(?:==|!=)', f_body) or \
                   re.search(rf'\b(?:require|assert|if)\s*\([^;]*(?:==|!=)\s*\b{alias}\b', f_body):
                    
                    found_line = f_start
                    for idx in range(f_start - 1, f_end):
                        if alias in lines[idx]:
                            found_line = idx + 1
                            break
                    
                    findings.append(StaticFinding(
                        id=f'finding-{uuid.uuid4().hex[:8]}',
                        contract=c_name,
                        function=func['name'],
                        line_start=t_vars.get(alias, found_line),
                        line_end=found_line,
                        category='tx-origin',
                        confidence=0.88,
                        message='tx.origin used for authorization (SWC-115)',
                        snippet=f"Usage of {alias}",
                        severity=CATEGORY_SEVERITY_MAP.get('tx-origin', 'High'),
                        swc_id=CATEGORY_SWC_MAP.get('tx-origin', 'SWC-115')
                    ))
                    reported_this_func = True
                    break
            
            if reported_this_func:
                continue
                
            for idx in range(f_start - 1, f_end):
                clean = re.sub(r'//.*$', '', lines[idx]).strip()
                call_match = re.search(r'\b([a-zA-Z0-9_]+)\s*\([^)]*\btx\.origin\b[^)]*\)', clean)
                if call_match:
                    helper_name = call_match.group(1)
                    for helper_func in functions:
                        if helper_func['name'] == helper_name:
                            h_lines = lines[helper_func['start']-1:helper_func['end']]
                            h_header = h_lines[0]
                            param_match = re.search(rf'function\s+{helper_name}\s*\(\s*address\s+(?:payable\s+)?([a-zA-Z0-9_]+)\s*\)', h_header)
                            if param_match:
                                p_name = param_match.group(1)
                                h_body = " ".join(re.sub(r'//.*$', '', l).strip() for l in h_lines)
                                if re.search(rf'\b(?:require|assert|if)\s*\([^;]*\b{p_name}\b\s*(?:==|!=)', h_body) or \
                                   re.search(rf'\b(?:require|assert|if)\s*\([^;]*(?:==|!=)\s*\b{p_name}\b', h_body):
                                    findings.append(StaticFinding(
                                        id=f'finding-{uuid.uuid4().hex[:8]}',
                                        contract=c_name,
                                        function=func['name'],
                                        line_start=idx + 1,
                                        line_end=idx + 1,
                                        category='tx-origin',
                                        confidence=0.88,
                                        message='tx.origin used for authorization via helper (SWC-115)',
                                        snippet=clean,
                                        severity=CATEGORY_SEVERITY_MAP.get('tx-origin', 'High'),
                                        swc_id=CATEGORY_SWC_MAP.get('tx-origin', 'SWC-115')
                                    ))
                                    break


    def _check_timestamp_dependence(self, lines: List[str], c_name: str, start: int, end: int, functions: List[Dict[str, Any]], findings: List[StaticFinding]):
        for func in functions:
            ts_vars = set()
            f_start = func['start']
            f_end = func['end']
            
            for idx in range(f_start - 1, f_end):
                line = lines[idx]
                clean = re.sub(r'//.*$', '', line).strip()
                if not clean:
                    continue
                    
                aliases_pat = r'\b(?:block\.timestamp|now' + ('|' + '|'.join(re.escape(v) for v in ts_vars) if ts_vars else '') + r')\b'
                
                assign_match = re.search(r'\b(?:uint\d*\s+)?([a-zA-Z0-9_]+)\s*=\s*' + aliases_pat, clean)
                if assign_match:
                    ts_vars.add(assign_match.group(1))
                
                aliases_pat_updated = r'\b(?:block\.timestamp|now' + ('|' + '|'.join(re.escape(v) for v in ts_vars) if ts_vars else '') + r')\b'
                    
                if re.search(aliases_pat_updated, clean):
                    line_no = idx + 1
                    f_name = self._find_enclosing_function(line_no, functions)

                    is_randomness = bool(re.search(aliases_pat_updated + r'\s*%', clean) or 
                                        re.search(r'%\s*' + aliases_pat_updated, clean) or
                                        (('keccak256' in clean or 'sha3' in clean) and re.search(aliases_pat_updated, clean)))

                    is_strict_equality = bool(re.search(aliases_pat_updated + r'\s*==|==\s*' + aliases_pat_updated, clean)) and \
                                         any(cond in clean for cond in ['require', 'assert', 'if'])

                    is_relative_comparison = bool(re.search(aliases_pat_updated + r'\s*(?:>=|<=|>|<)', clean) or re.search(r'(?:>=|<=|>|<)\s*' + aliases_pat_updated, clean))
                    is_sensitive_context = any(kw in f_name.lower() or kw in clean.lower() for kw in ['prize', 'winner', 'win', 'random', 'reward'])

                    if is_randomness:
                        findings.append(StaticFinding(
                            id=f'finding-{uuid.uuid4().hex[:8]}',
                            contract=c_name,
                            function=f_name,
                            line_start=line_no,
                            line_end=line_no,
                            category='timestamp-dependence',
                            confidence=0.88,
                            message='Timestamp Dependence as Randomness (SWC-116/120): Reliance on block.timestamp or now for randomness can be manipulated by miners.',
                            snippet=clean,
                            severity=CATEGORY_SEVERITY_MAP.get('timestamp-dependence', 'Medium'),
                            swc_id=CATEGORY_SWC_MAP.get('timestamp-dependence', 'SWC-116')
                        ))
                    elif is_strict_equality:
                        findings.append(StaticFinding(
                            id=f'finding-{uuid.uuid4().hex[:8]}',
                            contract=c_name,
                            function=f_name,
                            line_start=line_no,
                            line_end=line_no,
                            category='timestamp-dependence',
                            confidence=0.75,
                            message='Timestamp Dependence (SWC-116): Exact timestamp comparison (==) is dangerous because miners can manipulate block timestamps within small intervals.',
                            snippet=clean,
                            severity=CATEGORY_SEVERITY_MAP.get('timestamp-dependence', 'Medium'),
                            swc_id=CATEGORY_SWC_MAP.get('timestamp-dependence', 'SWC-116')
                        ))
                    elif is_relative_comparison and is_sensitive_context:
                        findings.append(StaticFinding(
                            id=f'finding-{uuid.uuid4().hex[:8]}',
                            contract=c_name,
                            function=f_name,
                            line_start=line_no,
                            line_end=line_no,
                            category='timestamp-dependence',
                            confidence=0.65,
                            message='Timestamp Dependence (SWC-116): Relative timestamp comparison in a security-sensitive context (e.g. prize/winner logic).',
                            snippet=clean,
                            severity=CATEGORY_SEVERITY_MAP.get('timestamp-dependence', 'Medium'),
                            swc_id=CATEGORY_SWC_MAP.get('timestamp-dependence', 'SWC-116')
                        ))

    def _has_valid_caller_authorization(self, f_header: str, f_lines: List[str], all_lines: List[str] = None, functions: List[Dict[str, Any]] = None, visited: set = None) -> bool:
        if visited is None: visited = set()
        if f_header in visited: return False
        visited.add(f_header)

        # 1. Recognized access-control modifiers in function header
        auth_modifier_patterns = [
            r'\bonlyOwner\b', r'\bonlyAdmin\b', r'\bauth\b', r'\brestricted\b',
            r'\brequiresAuth\b', r'\bonlyRole\b', r'\bhasRole\b'
        ]
        if any(re.search(pat, f_header, re.IGNORECASE) for pat in auth_modifier_patterns):
            return True


        if functions and all_lines:
            header_words = set(re.findall(r'\b[a-zA-Z0-9_]+\b', f_header))
            for func in functions:
                if func.get('type') == 'modifier' and func['name'] in header_words:
                    m_lines = all_lines[func['start'] - 1 : func['end']]
                    if self._has_valid_caller_authorization(all_lines[func['start'] - 1], m_lines, all_lines, functions, visited):
                        return True
            
            # check internal helper calls
            for line in f_lines:
                clean = re.sub(r'//.*$', '', line).strip()
                matches = re.findall(r'\b([a-zA-Z0-9_]+)\s*\(', clean)
                for called_func in matches:
                    for func in functions:
                        if func.get('type') == 'function' and func['name'] == called_func:
                            m_lines = all_lines[func['start'] - 1 : func['end']]
                            if self._has_valid_caller_authorization(all_lines[func['start'] - 1], m_lines, all_lines, functions, visited):
                                return True

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
        return False

    def _check_unprotected_selfdestruct(self, lines: List[str], c_name: str, functions: List[Dict[str, Any]], findings: List[StaticFinding]):
        for func in functions:
            f_start = func['start']
            f_end = func['end']
            f_header = lines[f_start - 1]
            f_lines = lines[f_start - 1 : f_end]
            
            has_auth = self._has_valid_caller_authorization(f_header, f_lines, lines, functions)

            for idx in range(f_start - 1, f_end):
                clean = re.sub(r'//.*$', '', lines[idx]).strip()
                if ('selfdestruct' in clean or 'suicide' in clean) and not clean.startswith('//'):
                    if not has_auth:
                        findings.append(StaticFinding(
                            id=f'finding-{uuid.uuid4().hex[:8]}',
                            contract=c_name,
                            function=func['name'],
                            line_start=idx + 1,
                            line_end=idx + 1,
                            category='unprotected-selfdestruct',
                            confidence=0.95,
                            message=f'Unprotected Selfdestruct (SWC-106): Function "{func["name"]}" allows destroying the contract without valid caller authorization or access-control modifiers.',
                            snippet=clean,
                            severity=CATEGORY_SEVERITY_MAP.get('unprotected-selfdestruct', 'Critical'),
                            swc_id=CATEGORY_SWC_MAP.get('unprotected-selfdestruct', 'SWC-106')
                        ))

    def _check_dangerous_delegatecall(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding], all_lines: List[str] = None):
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if 'delegatecall' in clean and not clean.startswith('//'):
                match = re.search(r'([a-zA-Z0-9_]+)\s*\.\s*delegatecall', clean)
                if not match:
                    continue
                target_var = match.group(1)
                
                is_safe = False
                if all_lines:
                    for l in all_lines:
                        # Check for constant or immutable
                        if re.search(rf'\b(?:constant|immutable)\s+{target_var}\b', l):
                            is_safe = True
                            break
                        # Check if target_var is directly assigned a hardcoded address 0x...
                        if re.search(rf'\b{target_var}\s*=\s*0x[a-fA-F0-9]{{40}}\b', l):
                            is_safe = True
                            break

                if is_safe:
                    continue

                findings.append(StaticFinding(
                    id=f'finding-{uuid.uuid4().hex[:8]}',
                    contract=c_name,
                    function=f_name,
                    line_start=offset + idx,
                    line_end=offset + idx,
                    category='dangerous-delegatecall',
                    confidence=0.92,
                    message='Dangerous Delegatecall (SWC-112): delegatecall executes code in the context of the calling contract, which can corrupt state if target is untrusted.',
                    snippet=clean,
                    severity=CATEGORY_SEVERITY_MAP.get('dangerous-delegatecall', 'Critical'),
                    swc_id=CATEGORY_SWC_MAP.get('dangerous-delegatecall', 'SWC-112')
                ))

    def _check_uninitialized_storage_pointers(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if re.search(r'\b[A-Z][a-zA-Z0-9_]+\s+[a-zA-Z0-9_]+\s*;', clean):
                if not ('memory' in clean or 'storage' in clean or 'calldata' in clean or 'uint' in clean or 'int' in clean or 'address' in clean or 'bool' in clean or 'bytes' in clean or 'string' in clean):
                    findings.append(StaticFinding(
                        id=f'finding-{uuid.uuid4().hex[:8]}',
                        contract=c_name,
                        function=f_name,
                        line_start=offset + idx,
                        line_end=offset + idx,
                        category='uninitialized-storage',
                        confidence=0.80,
                        message='Uninitialized Storage Pointer (SWC-109): Local variable declared without storage or memory keyword may overwrite contract storage.',
                        snippet=clean,
                        severity=CATEGORY_SEVERITY_MAP.get('uninitialized-storage', 'Medium'),
                        swc_id=CATEGORY_SWC_MAP.get('uninitialized-storage', 'SWC-109')
                    ))

    def _check_missing_zero_address_validation(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding], all_lines: List[str] = None):
        header = f_lines[0]
        addr_match = re.search(r'address(?:\s+payable)?\s+([a-zA-Z0-9_]+)', header)
        if addr_match:
            param = addr_match.group(1)
            has_assignment = False
            has_check = False
            assign_idx = 0
            
            zero_aliases = {'address(0)', '0x0000000000000000000000000000000000000000'}
            if all_lines:
                for line in all_lines:
                    m = re.search(r'address\s+(?:public\s+)?constant\s+([a-zA-Z0-9_]+)\s*=\s*(?:address\(\s*0\s*\)|0x0{40})', line)
                    if m:
                        zero_aliases.add(m.group(1))
            
            def _tokenize(identifier: str) -> set:
                tokens = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|\d+', identifier)
                return {t.lower() for t in tokens}
                
            for idx, line in enumerate(f_lines):
                clean = re.sub(r'//.*$', '', line).strip()
                
                for za in zero_aliases:
                    if f'{param} != {za}' in clean or f'{param} == {za}' in clean or f'require({param} != {za}' in clean or f'require({za} != {param}' in clean:
                        has_check = True
                        break
                
                assign_match = re.search(rf'\b([a-zA-Z0-9_]+)\s*=\s*{param}\b', clean)
                if assign_match and not clean.startswith('require'):
                    lhs = assign_match.group(1)
                    
                    privileged_keywords = {'owner', 'admin', 'controller'}
                    tokens = _tokenize(f_name) | _tokenize(param) | _tokenize(lhs)
                    
                    if tokens & privileged_keywords:
                        has_assignment = True
                        assign_idx = idx

            if has_assignment and not has_check:
                findings.append(StaticFinding(
                    id=f'finding-{uuid.uuid4().hex[:8]}',
                    contract=c_name,
                    function=f_name,
                    line_start=offset + assign_idx,
                    line_end=offset + assign_idx,
                    category='missing-zero-check',
                    confidence=0.75,
                    message='Missing Zero Address Validation (SWC-136): Privileged role assigned to a state variable without validation against address(0).',
                    snippet=f_lines[assign_idx].strip(),
                    severity=CATEGORY_SEVERITY_MAP.get('missing-zero-check', 'Low'),
                    swc_id=CATEGORY_SWC_MAP.get('missing-zero-check', 'SWC-136')
                ))

    def _check_missing_access_control(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding], all_lines: List[str] = None, functions: List[Dict[str, Any]] = None):
        f_lower = f_name.lower()
        if f_lower in ['setapprovalforall', 'approve', 'transferfrom', 'safeapprove', 'safetransferfrom']:
            return

        sensitive_prefixes = ['set', 'change', 'update', 'transferownership', 'withdraw', 'pause', 'unpause', 'mint', 'burn']
        is_sensitive = any(f_lower.startswith(pref) for pref in sensitive_prefixes)
        if not is_sensitive:
            return

        header = f_lines[0] if f_lines else ""
        if not ('public' in header or 'external' in header):
            return

        has_auth_modifier = any(mod in header for mod in ['onlyOwner', 'onlyAdmin', 'authorized', 'auth', 'restricted'])
        has_internal_check = False
        has_state_write = False

        has_auth = self._has_valid_caller_authorization(header, f_lines, all_lines, functions) if all_lines else has_auth_modifier

        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if 'require' in clean or 'assert' in clean:
                if 'msg.sender' in clean or 'owner' in clean or 'admin' in clean or 'role' in clean or 'tx.origin' in clean:
                    has_internal_check = True
            if self._is_state_write(clean):
                has_state_write = True

        if not has_auth and not has_internal_check and has_state_write:
            findings.append(StaticFinding(
                id=f'finding-{uuid.uuid4().hex[:8]}',
                contract=c_name,
                function=f_name,
                line_start=offset,
                line_end=offset + len(f_lines) - 1,
                category='missing-access-control',
                confidence=0.85,
                message=f'Missing Access Control (SWC-105): Sensitive function "{f_name}" alters state without authorization modifiers or caller validation.',
                snippet=f_lines[0].strip(),
                severity=CATEGORY_SEVERITY_MAP.get('missing-access-control', 'High'),
                swc_id=CATEGORY_SWC_MAP.get('missing-access-control', 'SWC-105')
            ))

    def _check_floating_pragma(self, lines: List[str], findings: List[StaticFinding]):
        for idx, line in enumerate(lines):
            clean = re.sub(r'//.*$', '', line).strip()
            # Find pragma solidity ...
            if clean.startswith("pragma solidity"):
                # if contains ^ or > or <
                if re.search(r'[\^\>\<\~]', clean):
                    findings.append(StaticFinding(
                        id=f'finding-{uuid.uuid4().hex[:8]}',
                        contract="Global",
                        function="",
                        line_start=idx + 1,
                        line_end=idx + 1,
                        category='floating-pragma',
                        confidence=0.95,
                        message='Floating Pragma (SWC-103): Contracts should be deployed with the same compiler version and flags that they have been tested with. Locking the pragma helps to ensure that contracts do not accidentally get deployed using another pragma.',
                        snippet=clean,
                        severity=CATEGORY_SEVERITY_MAP.get('floating-pragma', 'Low'),
                        swc_id=CATEGORY_SWC_MAP.get('floating-pragma', 'SWC-103')
                    ))

    def _check_ecrecover_validation(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if 'ecrecover' in clean and not clean.startswith('//'):
                # find assignment to a variable
                m = re.search(r'([a-zA-Z0-9_]+)\s*=\s*ecrecover', clean)
                if m:
                    signer_var = m.group(1)
                    # check if next lines have require(signer_var != address(0)) or similar
                    has_check = False
                    for post_idx in range(idx + 1, len(f_lines)):
                        post_line = re.sub(r'//.*$', '', f_lines[post_idx]).strip()
                        if re.search(rf'require\s*\(\s*{signer_var}\s*!=\s*address\(\s*0\s*\)', post_line) or \
                           re.search(rf'require\s*\(\s*address\(\s*0\s*\)\s*!=\s*{signer_var}', post_line):
                            has_check = True
                            break
                    if not has_check:
                        findings.append(StaticFinding(
                            id=f'finding-{uuid.uuid4().hex[:8]}',
                            contract=c_name,
                            function=f_name,
                            line_start=offset + idx,
                            line_end=offset + idx,
                            category='ecrecover-validation',
                            confidence=0.85,
                            message='Missing ecrecover Validation (SWC-117): ecrecover returns address(0) on invalid signatures, which must be explicitly checked.',
                            snippet=clean,
                            severity=CATEGORY_SEVERITY_MAP.get('ecrecover-validation', 'High'),
                            swc_id=CATEGORY_SWC_MAP.get('ecrecover-validation', 'SWC-117')
                        ))

    def _check_integer_overflow(self, lines: List[str], f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        is_safe_version = False
        for line in lines:
            if line.strip().startswith("pragma solidity"):
                m = re.search(r'0\.8\.\d+', line)
                if m:
                    is_safe_version = True
                break

        in_unchecked = False
        unchecked_start = -1
        
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            
            if 'unchecked' in clean and '{' in clean:
                in_unchecked = True
                unchecked_start = idx
                
            is_end = False
            if in_unchecked and '}' in clean and not 'unchecked' in clean:
                in_unchecked = False
                is_end = True
                
            if (not is_safe_version) or in_unchecked or is_end:
                if re.search(r'\b[a-zA-Z0-9_]+\s*(?:\+=|-=|\*=)\s*', clean) or \
                   re.search(r'\b[a-zA-Z0-9_]+\s*=\s*[a-zA-Z0-9_]+\s*[\+\-\*]\s*', clean):
                    
                    l_start = offset + idx
                    l_end = offset + idx
                    if unchecked_start != -1:
                        # find the closing brace index
                        l_start = offset + unchecked_start
                        for sub_idx in range(unchecked_start, len(f_lines)):
                            if '}' in f_lines[sub_idx]:
                                l_end = offset + sub_idx
                                break
                    
                    findings.append(StaticFinding(
                        id=f'finding-{uuid.uuid4().hex[:8]}',
                        contract=c_name,
                        function=f_name,
                        line_start=l_start,
                        line_end=l_end,
                        category='integer-overflow',
                        confidence=0.75,
                        message='Integer Overflow/Underflow (SWC-101): Math operation is vulnerable to overflow/underflow because it is either in an unchecked block or the Solidity version is < 0.8.0.',
                        snippet=clean,
                        severity=CATEGORY_SEVERITY_MAP.get('integer-overflow', 'High'),
                        swc_id=CATEGORY_SWC_MAP.get('integer-overflow', 'SWC-101')
                    ))

