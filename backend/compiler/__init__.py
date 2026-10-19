"""Solidity compiler and syntax validation package."""
from backend.compiler.solc_validator import (
    validate_solidity_source,
    compile_with_solc,
    fallback_syntax_check,
    get_installed_solc_versions,
    extract_pragma_version
)

__all__ = [
    "validate_solidity_source",
    "compile_with_solc",
    "fallback_syntax_check",
    "get_installed_solc_versions",
    "extract_pragma_version"
]
