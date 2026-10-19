"""
Solidity Compiler & Syntax Validation Module.
Provides compiler-driven diagnostics via solc (py-solc-x) with accurate source
locations, error types, line/column numbers, and comprehensive parser fallback.
"""
import re
import os
import tempfile
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


def extract_pragma_version(code: str) -> Optional[str]:
    """Extract Solidity pragma version specification from source code."""
    match = re.search(r'pragma\s+solidity\s+([^;]+);', code)
    if not match:
        return None
    spec = match.group(1).strip()
    return spec


def get_installed_solc_versions() -> List[str]:
    """Get list of locally installed solc compiler versions."""
    try:
        import solcx
        installed = solcx.get_installed_solc_versions()
        return [str(v).lstrip('v') for v in installed]
    except Exception as e:
        logger.debug(f"Could not query installed solc versions: {e}")
        return []


def select_compatible_solc_version(pragma_spec: Optional[str]) -> Optional[str]:
    """
    Select the best matching locally installed solc version for a pragma spec.
    Prefers exact version matches, then closest minor/patch version.
    Does NOT initiate blocking network downloads.
    """
    installed = get_installed_solc_versions()
    if not installed:
        return None

    if not pragma_spec:
        v08 = [v for v in installed if v.startswith("0.8")]
        return v08[-1] if v08 else installed[-1]

    clean_spec = pragma_spec.replace('^', '').replace('~', '').strip()
    # Direct match
    for v in installed:
        if v == clean_spec or v.startswith(clean_spec):
            return v

    num_match = re.search(r'(\d+\.\d+)(?:\.\d+)?', clean_spec)
    if num_match:
        major_minor = num_match.group(1)
        matching = [v for v in installed if v.startswith(major_minor)]
        if matching:
            return matching[-1]

    if "0.8" in clean_spec:
        v08 = [v for v in installed if v.startswith("0.8")]
        if v08:
            return v08[-1]

    if "0.4" in clean_spec:
        v04 = [v for v in installed if v.startswith("0.4")]
        if v04:
            return v04[-1]

    return None


def parse_solc_diagnostics(err_text: str) -> List[Dict[str, Any]]:
    """
    Parse standard solc compiler stdout/stderr diagnostic blocks.
    Handles both prefixed and unprefixed diagnostic blocks:
      ParserError: Expected ';' but got 'function'
       --> <stdin>:4:3:
    or
      Undeclared identifier.
       --> <stdin>:5:12:
    """
    diagnostics: List[Dict[str, Any]] = []
    if not err_text:
        return diagnostics

    # Normalize newlines
    normalized = err_text.replace('\r\n', '\n')

    # Regex to match diagnostic message and source location pointer
    block_pattern = re.compile(
        r'(?:^|\n)(?P<header>[^\n]+)\n\s*-->\s*(?P<source>[^:\n]+)(?::(?P<line>\d+)(?::(?P<col>\d+))?)?',
        re.MULTILINE
    )

    for m in block_pattern.finditer(normalized):
        header_line = m.group("header").strip()
        src = m.group("source").strip()
        line = int(m.group("line")) if m.group("line") else 1
        col = int(m.group("col")) if m.group("col") else 1

        # Skip command lines or internal markers
        if header_line.startswith(">") or header_line.startswith("command:"):
            continue

        is_warning = bool(re.search(r'\bwarning\b', header_line, re.IGNORECASE))
        
        # Determine error type and clean message
        clean_msg = header_line
        error_type = "CompilerError"

        type_match = re.match(r'^(ParserError|DeclarationError|TypeError|SyntaxError|DocstringParsingError|Error|Warning):\s*(.*)', header_line)
        if type_match:
            error_type = type_match.group(1)
            clean_msg = type_match.group(2).strip()
        else:
            low = header_line.lower()
            if "undeclared" in low or "declaration" in low or "not found" in low:
                error_type = "DeclarationError"
            elif "type" in low or "convertible" in low:
                error_type = "TypeError"
            elif "expected" in low or "syntax" in low or "parse" in low:
                error_type = "ParserError"
            elif is_warning:
                error_type = "Warning"

        diagnostics.append({
            "error_type": error_type,
            "severity": "warning" if is_warning else "error",
            "message": clean_msg,
            "source_location": src,
            "line": line,
            "column": col
        })

    # Fallback if no block matched but error text is present
    if not diagnostics and ("Error" in err_text or "error" in err_text or "Expected" in err_text):
        loc_match = re.search(r'-->\s*[^:\n]+:(\d+):(\d+):', err_text)
        line = int(loc_match.group(1)) if loc_match else 1
        col = int(loc_match.group(2)) if loc_match else 1

        clean_lines = [
            l.strip() for l in err_text.splitlines()
            if l.strip() and not l.strip().startswith(">") and not l.strip().startswith("command:")
        ]
        clean_msg = clean_lines[0] if clean_lines else "Compilation error"
        if "An error occurred during execution" in clean_msg and len(clean_lines) > 1:
            clean_msg = next((l for l in clean_lines if any(k in l for k in ["Error", "Expected", "Undeclared", "Type", "error"])), clean_lines[-1])

        diagnostics.append({
            "error_type": "CompilerError",
            "severity": "error",
            "message": clean_msg,
            "source_location": "<stdin>",
            "line": line,
            "column": col
        })

    return diagnostics


def compile_with_solc(source_code: str) -> Dict[str, Any]:
    """
    Attempt to compile Solidity source code using py-solc-x.
    Returns:
    - success: bool
    - compiler_available: bool
    - solc_version: Optional[str]
    - compiled_contracts: int
    - diagnostics: List[Dict[str, Any]]
    - error: Optional[str]
    """
    try:
        import solcx
    except ImportError:
        return {
            "success": False,
            "compiler_available": False,
            "unavailable": True,
            "error": "py-solc-x module is not installed."
        }

    pragma_spec = extract_pragma_version(source_code)
    target_version = select_compatible_solc_version(pragma_spec)

    if not target_version:
        installed = get_installed_solc_versions()
        return {
            "success": False,
            "compiler_available": False,
            "unavailable": True,
            "error": f"No compatible solc compiler version installed locally for pragma '{pragma_spec}'. Installed versions: {installed}."
        }

    try:
        solcx.set_solc_version(target_version)
    except Exception as e:
        return {
            "success": False,
            "compiler_available": False,
            "unavailable": True,
            "error": f"Failed to activate solc version {target_version}: {str(e)}"
        }

    try:
        compiled = solcx.compile_source(
            source_code,
            output_values=['abi', 'bin'],
            solc_version=target_version
        )
        return {
            "success": True,
            "compiler_available": True,
            "solc_version": target_version,
            "compiled_contracts": len(compiled) if compiled else 0,
            "diagnostics": [],
            "error": None
        }
    except solcx.exceptions.SolcError as e:
        err_content = e.stderr_data if hasattr(e, 'stderr_data') and e.stderr_data else str(e)
        diags = parse_solc_diagnostics(err_content)
        return {
            "success": False,
            "compiler_available": True,
            "solc_version": target_version,
            "compiled_contracts": 0,
            "diagnostics": diags,
            "error": diags[0]["message"] if diags else f"Compilation error: {err_content[:200]}"
        }
    except Exception as e:
        return {
            "success": False,
            "compiler_available": True,
            "solc_version": target_version,
            "compiled_contracts": 0,
            "diagnostics": [{
                "error_type": "CompilerException",
                "severity": "error",
                "message": str(e),
                "source_location": "<stdin>",
                "line": 1,
                "column": 1
            }],
            "error": str(e)
        }


def fallback_syntax_check(source_code: str) -> Dict[str, Any]:
    """
    Parser-based fallback syntax validation when a compiler is unavailable.
    Detects missing semicolons, unmatched braces, unmatched parentheses,
    unmatched brackets, unclosed string literals, and malformed declarations.
    """
    errors: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    if not source_code or not source_code.strip():
        return {
            "is_valid": False,
            "errors": [{
                "error_type": "SyntaxError",
                "severity": "error",
                "message": "Empty or whitespace-only source code",
                "line": 1,
                "column": 1,
                "source_location": "<stdin>"
            }],
            "warnings": [],
            "compiler_available": False,
            "compiler_executed": False
        }

    lines = source_code.splitlines()

    brace_stack: List[Tuple[str, int, int]] = []
    paren_stack: List[Tuple[str, int, int]] = []
    bracket_stack: List[Tuple[str, int, int]] = []

    in_block_comment = False
    in_string = False
    string_quote = ''
    string_start_line = 1
    string_start_col = 1

    var_decl_pattern = re.compile(
        r'^(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping\s*\(.*?\))(?:\s+(?:public|private|internal|constant|immutable|payable))*\s+[a-zA-Z0-9_]+(?:\s*=\s*[^;{]+)?$'
    )

    for line_idx, line in enumerate(lines, start=1):
        clean_line = line.strip()
        col_idx = 0
        n = len(line)

        if not in_block_comment and clean_line.startswith("//"):
            continue

        while col_idx < n:
            ch = line[col_idx]
            next_ch = line[col_idx + 1] if col_idx + 1 < n else ''

            if in_block_comment:
                if ch == '*' and next_ch == '/':
                    in_block_comment = False
                    col_idx += 2
                    continue
                col_idx += 1
                continue

            if in_string:
                if ch == '\\':
                    col_idx += 2
                    continue
                if ch == string_quote:
                    in_string = False
                col_idx += 1
                continue

            if ch == '/' and next_ch == '/':
                break
            if ch == '/' and next_ch == '*':
                in_block_comment = True
                col_idx += 2
                continue

            if ch in ('"', "'"):
                in_string = True
                string_quote = ch
                string_start_line = line_idx
                string_start_col = col_idx + 1
                col_idx += 1
                continue

            if ch == '{':
                brace_stack.append(('{', line_idx, col_idx + 1))
            elif ch == '}':
                if brace_stack:
                    brace_stack.pop()
                else:
                    errors.append({
                        "error_type": "SyntaxError",
                        "severity": "error",
                        "message": "Unmatched closing brace '}'",
                        "line": line_idx,
                        "column": col_idx + 1,
                        "source_location": "<stdin>"
                    })

            elif ch == '(':
                paren_stack.append(('(', line_idx, col_idx + 1))
            elif ch == ')':
                if paren_stack:
                    paren_stack.pop()
                else:
                    errors.append({
                        "error_type": "SyntaxError",
                        "severity": "error",
                        "message": "Unmatched closing parenthesis ')'",
                        "line": line_idx,
                        "column": col_idx + 1,
                        "source_location": "<stdin>"
                    })

            elif ch == '[':
                bracket_stack.append(('[', line_idx, col_idx + 1))
            elif ch == ']':
                if bracket_stack:
                    bracket_stack.pop()
                else:
                    errors.append({
                        "error_type": "SyntaxError",
                        "severity": "error",
                        "message": "Unmatched closing bracket ']'",
                        "line": line_idx,
                        "column": col_idx + 1,
                        "source_location": "<stdin>"
                    })

            col_idx += 1

        # Check for missing semicolons on statements
        if not in_block_comment and not in_string and clean_line:
            code_part = re.sub(r'//.*$', '', clean_line).strip()
            if code_part:
                needs_semicolon = False
                
                if var_decl_pattern.match(code_part):
                    needs_semicolon = True

                if re.match(r'^(?:return\b|emit\b|require\s*\(|assert\s*\(|revert\b)', code_part):
                    if not code_part.endswith(';') and not code_part.endswith('{') and not code_part.endswith(','):
                        needs_semicolon = True

                if re.match(r'^[a-zA-Z0-9_\[\]\.]+\s*(?:=|\+=|-=|\*=|/=|%=)\s*[^;{]+$', code_part):
                    needs_semicolon = True

                if needs_semicolon and not code_part.endswith((';', '{', '}', '(', ',', '\\', '+', '-', '*', '/')):
                    errors.append({
                        "error_type": "ParserError",
                        "severity": "error",
                        "message": "Expected ';' (semicolon) but reached end of line",
                        "line": line_idx,
                        "column": len(line) + 1,
                        "source_location": "<stdin>"
                    })

    if in_string:
        errors.append({
            "error_type": "ParserError",
            "severity": "error",
            "message": f"Unclosed string literal starting with quote {string_quote}",
            "line": string_start_line,
            "column": string_start_col,
            "source_location": "<stdin>"
        })

    for ch, l, c in brace_stack:
        errors.append({
            "error_type": "ParserError",
            "severity": "error",
            "message": "Missing closing brace '}'",
            "line": l,
            "column": c,
            "source_location": "<stdin>"
        })

    for ch, l, c in paren_stack:
        errors.append({
            "error_type": "ParserError",
            "severity": "error",
            "message": "Missing closing parenthesis ')'",
            "line": l,
            "column": c,
            "source_location": "<stdin>"
        })

    for ch, l, c in bracket_stack:
        errors.append({
            "error_type": "ParserError",
            "severity": "error",
            "message": "Missing closing bracket ']'",
            "line": l,
            "column": c,
            "source_location": "<stdin>"
        })

    if not extract_pragma_version(source_code):
        warnings.append({
            "error_type": "Warning",
            "severity": "warning",
            "message": "Source file does not specify a 'pragma solidity' compiler version.",
            "line": 1,
            "column": 1,
            "source_location": "<stdin>"
        })

    return {
        "is_valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "compiler_available": False,
        "compiler_executed": False
    }


def validate_solidity_source(source_code: str) -> Dict[str, Any]:
    """
    Complete Solidity syntax and compiler validation pipeline.
    Uses the project's configured Solidity compiler when available,
    and falls back to comprehensive AST/syntax checking if unavailable.
    """
    if not source_code or not source_code.strip():
        return {
            "is_valid": False,
            "compiler_available": False,
            "compiler_executed": False,
            "errors": [{
                "error_type": "SyntaxError",
                "severity": "error",
                "message": "Source code is empty.",
                "line": 1,
                "column": 1,
                "source_location": "<stdin>"
            }],
            "warnings": [],
            "solc_version": None,
            "diagnostics_summary": "Source code is empty."
        }

    compile_result = compile_with_solc(source_code)

    if compile_result.get("compiler_available"):
        if compile_result.get("success"):
            return {
                "is_valid": True,
                "compiler_available": True,
                "compiler_executed": True,
                "solc_version": compile_result.get("solc_version"),
                "errors": [],
                "warnings": [d for d in compile_result.get("diagnostics", []) if d.get("severity") == "warning"],
                "compiled_contracts": compile_result.get("compiled_contracts", 0),
                "diagnostics_summary": f"Solidity validation passed using solc {compile_result.get('solc_version')}."
            }
        else:
            all_diags = compile_result.get("diagnostics", [])
            errors = [d for d in all_diags if d.get("severity") != "warning"]
            warnings = [d for d in all_diags if d.get("severity") == "warning"]
            
            if not errors and compile_result.get("error"):
                errors.append({
                    "error_type": "CompilerError",
                    "severity": "error",
                    "message": compile_result.get("error"),
                    "line": 1,
                    "column": 1,
                    "source_location": "<stdin>"
                })

            summary = f"Compiler validation failed with {len(errors)} error(s) using solc {compile_result.get('solc_version')}."
            return {
                "is_valid": False,
                "compiler_available": True,
                "compiler_executed": True,
                "solc_version": compile_result.get("solc_version"),
                "errors": errors,
                "warnings": warnings,
                "compiled_contracts": 0,
                "diagnostics_summary": summary
            }

    fallback = fallback_syntax_check(source_code)
    fallback["solc_version"] = None
    reason = compile_result.get("error", "Solidity compiler unavailable")
    if fallback["is_valid"]:
        fallback["diagnostics_summary"] = f"Basic syntax passed ({reason})."
    else:
        fallback["diagnostics_summary"] = f"Syntax validation failed with {len(fallback['errors'])} error(s) ({reason})."
    return fallback
