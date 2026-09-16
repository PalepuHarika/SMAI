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

                self._check_reentrancy(f_lines, c_name, f_name, f_start, findings)
                self._check_unchecked_calls(f_lines, c_name, f_name, f_start, findings)
                self._check_dangerous_delegatecall(f_lines, c_name, f_name, f_start, findings)
                self._check_uninitialized_storage_pointers(f_lines, c_name, f_name, f_start, findings)
                self._check_missing_zero_address_validation(f_lines, c_name, f_name, f_start, findings)
                self._check_missing_access_control(f_lines, c_name, f_name, f_start, findings)

        return findings

    def _is_state_write(self, clean_line: str) -> bool:
        if clean_line.startswith('require') or clean_line.startswith('if') or clean_line.startswith('emit') or \
           clean_line.startswith('assert') or clean_line.startswith('revert') or clean_line.startswith('return'):
            return False
            
        if not re.search(r'(=|\+=|-=|\*=|/=|%=|\+\+|--)', clean_line):
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
        brace_count = 0
        found_first = False
        for idx in range(start_idx, len(lines)):
            line = lines[idx]
            clean_line = re.sub(r'//.*$', '', line)
            clean_line = re.sub(r'/\*.*?\*/', '', clean_line)
            for ch in clean_line:
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

    def _check_reentrancy(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        header = f_lines[0] if f_lines else ""
        if re.search(r'\b(nonReentrant|reentrancyGuard)\b', header, re.IGNORECASE):
            return

        call_line_idx = -1
        call_snippet = ""

        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if re.search(r"\.(?:call\s*(?:\{|\()|transfer\s*\(|send\s*\()", clean):
                call_line_idx = idx
                call_snippet = clean
                break

        if call_line_idx != -1:
            for post_idx in range(call_line_idx + 1, len(f_lines)):
                post_line = re.sub(r'//.*$', '', f_lines[post_idx]).strip()
                is_assignment = self._is_state_write(post_line)
                is_call = bool(re.search(r'^\s*[a-zA-Z0-9_]+\s*\(', post_line))
                if (is_assignment or is_call) and \
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

            # 1. Inline checked: require(target.call(...)), if (target.call(...)), assert(...)
            if clean.startswith('require(') or clean.startswith('assert(') or clean.startswith('if (') or clean.startswith('if('):
                continue

            # 2. Check if return value is captured in a boolean variable or tuple
            capture_match = re.search(r'\(?\s*bool\s+([a-zA-Z0-9_]+)', clean)
            if capture_match:
                var_name = capture_match.group(1)
                is_checked = False
                for post_idx in range(idx + 1, len(f_lines)):
                    post_line = re.sub(r'//.*$', '', f_lines[post_idx]).strip()
                    if re.search(rf'\b(?:require|assert|if)\s*\([^)]*\b{var_name}\b', post_line):
                        is_checked = True
                        break
                if is_checked:
                    continue

            # Return value ignored or captured but never checked
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
            tx_origin_vars = set()
            f_start = func['start']
            f_end = func['end']
            for idx in range(f_start - 1, f_end):
                line = lines[idx]
                clean = re.sub(r'//.*$', '', line).strip()
                
                assignment_match = re.search(r'\b(?:address\s+)?([a-zA-Z0-9_]+)\s*=\s*tx\.origin\b', clean)
                if assignment_match:
                    tx_origin_vars.add(assignment_match.group(1))

                aliases_pattern = r'\b(' + '|'.join([r'tx\.origin'] + [re.escape(v) for v in tx_origin_vars]) + r')\b'
                
                if re.search(aliases_pattern, clean) and not clean.startswith('//'):
                    if clean.startswith('emit ') or 'emit ' in clean:
                        continue

                    is_comparison = bool(re.search(rf'{aliases_pattern}\s*(?:==|!=)|(?:==|!=)\s*{aliases_pattern}', clean))
                    is_guard = any(guard in clean for guard in ['require(', 'assert(', 'if (', 'if('])
                    is_auth_call = bool(re.search(rf'^\s*[a-zA-Z0-9_]+\s*\([^)]*{aliases_pattern}[^)]*\)\s*;', clean))

                    is_auth_misuse = is_comparison or (is_guard and ('==' in clean or '!=' in clean or 'isAuthorized' in clean or 'hasRole' in clean or 'owner' in clean or 'admin' in clean)) or is_auth_call

                    if not is_auth_misuse:
                        continue

                    line_no = idx + 1
                    f_name = self._find_enclosing_function(line_no, functions)

                    funcs_to_report = [f_name]
                    for m_func in functions:
                        if m_func.get('type') == 'modifier' and m_func['name'] == f_name:
                            funcs_to_report = []
                            for other_func in functions:
                                if other_func.get('type') != 'modifier':
                                    header = lines[other_func['start'] - 1]
                                    if re.search(rf'\b{f_name}\b', header):
                                        funcs_to_report.append(other_func['name'])
                            if not funcs_to_report:
                                funcs_to_report = [f_name]
                            break

                    for report_f_name in funcs_to_report:
                        findings.append(StaticFinding(
                        id=f'finding-{uuid.uuid4().hex[:8]}',
                        contract=c_name,
                        function=report_f_name,
                        line_start=line_no,
                        line_end=line_no,
                        category='tx-origin',
                        confidence=0.92,
                        message='Authorization through tx.origin (SWC-115): Use of tx.origin for authorization makes the contract vulnerable to phishing attacks.',
                        snippet=clean,
                        severity=CATEGORY_SEVERITY_MAP.get('tx-origin', 'High'),
                        swc_id=CATEGORY_SWC_MAP.get('tx-origin', 'SWC-115')
                    ))

    def _check_timestamp_dependence(self, lines: List[str], c_name: str, start: int, end: int, functions: List[Dict[str, Any]], findings: List[StaticFinding]):
        for idx in range(start - 1, end):
            line = lines[idx]
            clean = re.sub(r'//.*$', '', line).strip()
            if ('block.timestamp' in clean or ' now ' in clean or clean.startswith('now ') or ' now;' in clean) and not clean.startswith('//'):
                line_no = idx + 1
                f_name = self._find_enclosing_function(line_no, functions)

                # 1. Dangerous: randomness (modulo % or keccak256/sha3 hash)
                is_randomness = bool(re.search(r'(?:block\.timestamp|now)\s*%', clean) or 
                                    re.search(r'%\s*(?:block\.timestamp|now)', clean) or
                                    (('keccak256' in clean or 'sha3' in clean) and ('block.timestamp' in clean or 'now' in clean)))

                # 2. Dangerous: strict equality comparison (==)
                is_strict_equality = bool(re.search(r'(?:block\.timestamp|now)\s*==|==\s*(?:block\.timestamp|now)', clean)) and \
                                     any(cond in clean for cond in ['require', 'assert', 'if'])

                # 3. Dangerous relative comparisons in sensitive contexts
                is_relative_comparison = bool(re.search(r'(?:block\.timestamp|now)\s*(?:>=|<=|>|<)', clean) or re.search(r'(?:>=|<=|>|<)\s*(?:block\.timestamp|now)', clean))
                is_sensitive_context = any(kw in f_name.lower() or kw in clean.lower() for kw in ['prize', 'winner', 'win', 'random', 'reward', 'fee', 'transfer'])

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

    def _has_valid_caller_authorization(self, f_header: str, f_lines: List[str]) -> bool:
        # 1. Recognized access-control modifiers in function header
        auth_modifier_patterns = [
            r'\bonlyOwner\b', r'\bonlyAdmin\b', r'\bauth\b', r'\brestricted\b',
            r'\brequiresAuth\b', r'\bonlyRole\b', r'\bhasRole\b'
        ]
        if any(re.search(pat, f_header, re.IGNORECASE) for pat in auth_modifier_patterns):
            return True

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
        return False

    def _check_unprotected_selfdestruct(self, lines: List[str], c_name: str, functions: List[Dict[str, Any]], findings: List[StaticFinding]):
        for func in functions:
            f_start = func['start']
            f_end = func['end']
            f_header = lines[f_start - 1]
            f_lines = lines[f_start - 1 : f_end]
            
            has_auth = self._has_valid_caller_authorization(f_header, f_lines)

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

    def _check_dangerous_delegatecall(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if 'delegatecall' in clean and not clean.startswith('//'):
                match = re.search(r'([a-zA-Z0-9_]+)\s*\.\s*delegatecall', clean)
                target_var = match.group(1) if match else None
                # If target is safe/trusted (e.g. trustedTarget)
                if target_var and 'trusted' in target_var.lower():
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

    def _check_missing_zero_address_validation(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        header = f_lines[0]
        addr_match = re.search(r'address(?:\s+payable)?\s+([a-zA-Z0-9_]+)', header)
        if addr_match:
            param = addr_match.group(1)
            has_assignment = False
            has_check = False
            assign_idx = 0
            
            def _tokenize(identifier: str) -> set:
                tokens = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|\d+', identifier)
                return {t.lower() for t in tokens}
                
            for idx, line in enumerate(f_lines):
                clean = re.sub(r'//.*$', '', line).strip()
                if f'address(0)' in clean or f'{param} != address(0)' in clean or f'{param} == address(0)' in clean:
                    has_check = True
                
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
                    confidence=0.70,
                    message=f'Missing Zero Address Validation: Privileged parameter "{param}" assigned to state variable without validation against address(0).',
                    snippet=f_lines[assign_idx].strip(),
                    severity=CATEGORY_SEVERITY_MAP.get('missing-zero-check', 'Low'),
                    swc_id=CATEGORY_SWC_MAP.get('missing-zero-check', 'SWC-136')
                ))

    def _check_missing_access_control(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        sensitive_prefixes = ['set', 'change', 'update', 'transferownership', 'withdraw', 'pause', 'unpause', 'mint', 'burn']
        f_lower = f_name.lower()
        is_sensitive = any(f_lower.startswith(pref) for pref in sensitive_prefixes)
        if not is_sensitive:
            return

        header = f_lines[0] if f_lines else ""
        if not ('public' in header or 'external' in header):
            return

        has_auth_modifier = any(mod in header for mod in ['onlyOwner', 'onlyAdmin', 'authorized', 'auth', 'restricted'])
        has_internal_check = False
        has_state_write = False

        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if 'require' in clean or 'assert' in clean:
                if 'msg.sender' in clean or 'owner' in clean or 'admin' in clean or 'role' in clean or 'tx.origin' in clean:
                    has_internal_check = True
            if self._is_state_write(clean):
                has_state_write = True

        if not has_auth_modifier and not has_internal_check and has_state_write:
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
