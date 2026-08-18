import re
import uuid
from typing import List, Dict, Any, Tuple, Optional
from backend.core.finding import StaticFinding

class SolidityStaticAnalyzer:
    """
    Solidity static analysis engine that extracts contract structures
    and flags suspicious security patterns based on AST and heuristic rules.
    """

    def __init__(self):
        self.contract_pattern = re.compile(r'\b(?:contract|library|interface)\s+([a-zA-Z0-9_]+)', re.MULTILINE)
        self.func_pattern = re.compile(r'\bfunction\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)', re.MULTILINE)

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

            self._check_tx_origin(lines, c_name, c_start, c_end, findings)
            self._check_timestamp_dependence(lines, c_name, c_start, c_end, findings)
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

        return findings

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
            match = re.search(r'\b(?:function\s+([a-zA-Z0-9_]+)|fallback\s*\(|receive\s*\()', line)
            if match:
                f_name = match.group(1) if match.group(1) else ('receive' if 'receive' in line else 'fallback')
                f_start = i + 1
                f_end = self._find_closing_brace(lines, i)
                functions.append({
                    'name': f_name,
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

    def _check_reentrancy(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        call_line_idx = -1
        call_snippet = ""

        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if re.search(r"\.(?:call\s*(?:\{|\()|delegatecall\s*(?:\{|\()|transfer\s*\(|send\s*\()", clean):
                call_line_idx = idx
                call_snippet = clean
                break

        if call_line_idx != -1:
            for post_idx in range(call_line_idx + 1, len(f_lines)):
                post_line = re.sub(r'//.*$', '', f_lines[post_idx]).strip()
                if re.search(r'\b[a-zA-Z0-9_\[\]\.]+\s*(=|\+=|-=|\*=|/=|\+\+|--)', post_line) and not post_line.startswith('require') and not post_line.startswith('if') and not post_line.startswith('emit'):
                    findings.append(StaticFinding(
                        id=f'finding-{uuid.uuid4().hex[:8]}',
                        contract=c_name,
                        function=f_name,
                        line_start=offset + call_line_idx,
                        line_end=offset + post_idx,
                        category='reentrancy',
                        confidence=0.88,
                        message=f'Potential Reentrancy (SWC-107): External call at line {offset + call_line_idx} occurs before state variable assignment at line {offset + post_idx}.',
                        snippet=f'Call: {call_snippet} | State update: {post_line}'
                    ))
                    break

    def _check_unchecked_calls(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if re.search(r'\b[a-zA-Z0-9_]+\s*\.\s*(call|delegatecall|send)\s*\(', clean):
                if not (clean.startswith('require') or clean.startswith('if') or clean.startswith('(') or clean.startswith('bool ')):
                    findings.append(StaticFinding(
                        id=f'finding-{uuid.uuid4().hex[:8]}',
                        contract=c_name,
                        function=f_name,
                        line_start=offset + idx,
                        line_end=offset + idx,
                        category='unchecked-call',
                        confidence=0.85,
                        message=f'Unchecked Low-Level Call (SWC-104): The return value of low-level external call is not checked.',
                        snippet=clean
                    ))

    def _check_tx_origin(self, lines: List[str], c_name: str, start: int, end: int, findings: List[StaticFinding]):
        for idx in range(start - 1, end):
            line = lines[idx]
            clean = re.sub(r'//.*$', '', line).strip()
            if 'tx.origin' in clean and not clean.startswith('//'):
                findings.append(StaticFinding(
                    id=f'finding-{uuid.uuid4().hex[:8]}',
                    contract=c_name,
                    function='unknown',
                    line_start=idx + 1,
                    line_end=idx + 1,
                    category='tx-origin',
                    confidence=0.92,
                    message='Authorization through tx.origin (SWC-115): Use of tx.origin for authorization makes the contract vulnerable to phishing attacks.',
                    snippet=clean
                ))

    def _check_timestamp_dependence(self, lines: List[str], c_name: str, start: int, end: int, findings: List[StaticFinding]):
        for idx in range(start - 1, end):
            line = lines[idx]
            clean = re.sub(r'//.*$', '', line).strip()
            if ('block.timestamp' in clean or ' now ' in clean) and ('require' in clean or 'if' in clean or '==' in clean or '%' in clean):
                findings.append(StaticFinding(
                    id=f'finding-{uuid.uuid4().hex[:8]}',
                    contract=c_name,
                    function='unknown',
                    line_start=idx + 1,
                    line_end=idx + 1,
                    category='timestamp-dependence',
                    confidence=0.75,
                    message='Timestamp Dependence (SWC-116): Reliance on block.timestamp or now can be manipulated by miners within small intervals.',
                    snippet=clean
                ))

    def _check_unprotected_selfdestruct(self, lines: List[str], c_name: str, functions: List[Dict[str, Any]], findings: List[StaticFinding]):
        for func in functions:
            f_start = func['start']
            f_end = func['end']
            f_header = lines[f_start - 1]
            has_auth = any(mod in f_header for mod in ['onlyOwner', 'onlyAdmin', 'auth', 'require'])
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
                            message='Unprotected Selfdestruct (SWC-106): Function allows destroying the contract without proper access control modifiers.',
                            snippet=clean
                        ))

    def _check_dangerous_delegatecall(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        for idx, line in enumerate(f_lines):
            clean = re.sub(r'//.*$', '', line).strip()
            if 'delegatecall' in clean and not clean.startswith('//'):
                findings.append(StaticFinding(
                    id=f'finding-{uuid.uuid4().hex[:8]}',
                    contract=c_name,
                    function=f_name,
                    line_start=offset + idx,
                    line_end=offset + idx,
                    category='dangerous-delegatecall',
                    confidence=0.90,
                    message='Dangerous Delegatecall (SWC-112): delegatecall executes code in the context of the calling contract, which can corrupt state if target is untrusted.',
                    snippet=clean
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
                        snippet=clean
                    ))

    def _check_missing_zero_address_validation(self, f_lines: List[str], c_name: str, f_name: str, offset: int, findings: List[StaticFinding]):
        header = f_lines[0]
        addr_match = re.search(r'address(?:\s+payable)?\s+([a-zA-Z0-9_]+)', header)
        if addr_match:
            param = addr_match.group(1)
            has_assignment = False
            has_check = False
            assign_idx = 0
            for idx, line in enumerate(f_lines):
                clean = re.sub(r'//.*$', '', line).strip()
                if f'address(0)' in clean or f'{param} != address(0)' in clean or f'{param} == address(0)' in clean:
                    has_check = True
                if re.search(rf'\b[a-zA-Z0-9_]+\s*=\s*{param}\b', clean) and not clean.startswith('require'):
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
                    message=f'Missing Zero Address Validation: Parameter "{param}" assigned to state variable without validation against address(0).',
                    snippet=f_lines[assign_idx].strip()
                ))
