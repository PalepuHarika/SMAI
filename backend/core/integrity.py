import hashlib
import json
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel

ANALYZER_VERSION: str = "1.0.0"

def hash_source_sha256(source: Union[str, bytes]) -> str:
    """
    Computes deterministic SHA-256 hex digest for Solidity source code bytes/text.
    Handles Unicode encoding and empty inputs safely.
    """
    if source is None:
        source = ""
    if isinstance(source, str):
        data = source.encode("utf-8")
    else:
        data = bytes(source)
    return hashlib.sha256(data).hexdigest()

def hash_source_keccak256(source: Union[str, bytes]) -> Optional[str]:
    """
    Computes Keccak-256 hex digest for Solidity source code if pycryptodome/eth_hash is available.
    Returns None if no Keccak-256 provider is found.
    """
    if source is None:
        source = ""
    if isinstance(source, str):
        data = source.encode("utf-8")
    else:
        data = bytes(source)

    try:
        from Crypto.Hash import keccak  # pycryptodome
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.hexdigest()
    except Exception:
        try:
            import eth_hash.auto as eth_hash_auto
            return eth_hash_auto.keccak(data).hex()
        except Exception:
            return None

def canonical_json_dumps(data: Any) -> str:
    """
    Produces deterministic, canonical JSON serialization:
    - Keys sorted at all levels
    - Separators without whitespace (',', ':')
    - Unicode characters preserved (ensure_ascii=False)
    - Default str fallback for non-primitive types
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

def canonicalize_finding(finding: Union[Dict[str, Any], BaseModel, Any]) -> Dict[str, Any]:
    """
    Extracts a normalized, deterministic dictionary representation of a security finding.
    Explicitly excludes ephemeral fields such as random finding_id UUIDs, timestamps,
    or execution durations.
    """
    if isinstance(finding, BaseModel):
        data = finding.model_dump()
    elif isinstance(finding, dict):
        data = dict(finding)
    elif hasattr(finding, "__dict__"):
        data = dict(finding.__dict__)
    else:
        data = {}

    affected_lines = data.get("affected_lines") or []
    if isinstance(affected_lines, (list, tuple)):
        clean_lines = sorted(list(set(int(x) for x in affected_lines if isinstance(x, (int, str)) and str(x).isdigit())))
    else:
        clean_lines = []

    category = str(data.get("vulnerability") or data.get("category") or "").strip().lower()
    severity = str(data.get("severity") or "Medium").strip().title()
    contract = str(data.get("contract") or "").strip()
    function = str(data.get("function") or "").strip()
    swc_id = str(data.get("swc_id") or "").strip().upper()
    original_code = str(data.get("original_code") or data.get("snippet") or "").strip()
    verification_status = str(data.get("verification_status") or "UNVERIFIED").strip().upper()

    conf_val = data.get("confidence")
    try:
        conf_float = round(float(conf_val), 3) if conf_val is not None else 0.0
    except (ValueError, TypeError):
        conf_float = 0.0

    return {
        "affected_lines": clean_lines,
        "category": category,
        "confidence": conf_float,
        "contract": contract,
        "explanation": str(data.get("explanation") or "").strip(),
        "fixed_code": str(data.get("fixed_code") or "").strip(),
        "function": function,
        "original_code": original_code,
        "recommendation": str(data.get("recommendation") or "").strip(),
        "severity": severity,
        "swc_id": swc_id,
        "verification_status": verification_status,
    }

def compute_finding_hash(finding: Union[Dict[str, Any], BaseModel, Any]) -> str:
    """
    Computes a deterministic SHA-256 hash of a single finding's canonical representation.
    """
    canon = canonicalize_finding(finding)
    canon_str = canonical_json_dumps(canon)
    return hashlib.sha256(canon_str.encode("utf-8")).hexdigest()

def compute_findings_hash(findings: List[Union[Dict[str, Any], BaseModel, Any]]) -> str:
    """
    Computes a deterministic digest for a collection of findings.
    Sorts individual finding hashes lexicographically before hashing to guarantee
    invariance against list ordering or database insertion order.
    """
    if not findings:
        return hashlib.sha256(b"[]").hexdigest()

    f_hashes = [compute_finding_hash(f) for f in findings]
    sorted_hashes = sorted(f_hashes)
    canon_str = canonical_json_dumps(sorted_hashes)
    return hashlib.sha256(canon_str.encode("utf-8")).hexdigest()

def compute_findings_merkle_root(findings: List[Union[Dict[str, Any], BaseModel, Any]]) -> str:
    """
    Computes a deterministic Merkle root over the sorted finding hashes.
    """
    if not findings:
        return hash_source_sha256("")

    f_hashes = sorted([compute_finding_hash(f) for f in findings])
    current_level = f_hashes

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0]

def compute_report_hash(
    source_hash: str,
    findings_hash: str,
    security_score: Optional[int],
    risk_level: Optional[str],
    analysis_mode: str
) -> str:
    """
    Computes deterministic canonical report hash.
    Strictly depends only on:
    - source_hash
    - canonical findings digest (findings_hash)
    - security score
    - risk level
    - analysis mode (normalized)

    Must NOT include random UUIDs, timestamps, or database IDs.
    """
    mode_str = str(analysis_mode or "").strip().lower()
    mode_aliases = {"a": "rag", "b": "ai", "c": "hybrid"}
    normalized_mode = mode_aliases.get(mode_str, mode_str)

    score_val = None
    if security_score is not None:
        try:
            score_val = int(round(float(security_score)))
        except (ValueError, TypeError):
            score_val = None

    payload = {
        "analysis_mode": normalized_mode,
        "findings_hash": str(findings_hash or ""),
        "risk_level": str(risk_level or "").strip(),
        "security_score": score_val,
        "source_hash": str(source_hash or "").strip().lower(),
    }
    canon_str = canonical_json_dumps(payload)
    return hashlib.sha256(canon_str.encode("utf-8")).hexdigest()

def extract_solidity_pragma(source_code: str) -> Optional[str]:
    """
    Safely extracts the Solidity compiler pragma directive from source code.
    Example: 'pragma solidity ^0.8.0;' -> '^0.8.0'
    Returns None if no pragma statement is found.
    """
    if not source_code:
        return None
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source_code, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

def get_git_commit() -> Optional[str]:
    """
    Safely retrieves the current git commit SHA from environment variables or git repository.
    Returns None if unavailable.
    """
    env_commit = os.getenv("GIT_COMMIT") or os.getenv("COMMIT_SHA")
    if env_commit:
        return env_commit.strip()

    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            timeout=2.0
        ).decode("utf-8").strip()
        if commit:
            return commit
    except Exception:
        pass

    return None

def get_knowledge_base_version() -> Optional[str]:
    """
    Returns the knowledge base integrity version / fingerprint if the file exists.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    kb_path = os.path.join(base_dir, "data", "knowledge_base.json")
    if os.path.exists(kb_path):
        try:
            with open(kb_path, "rb") as f:
                content = f.read()
            return f"kb-sha256:{hashlib.sha256(content).hexdigest()[:12]}"
        except Exception:
            return None
    return None
