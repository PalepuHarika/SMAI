import json
from backend.core.finding import VerifiedVulnerability

schema = VerifiedVulnerability.model_json_schema()
schema.pop("title", None)
schema.pop("description", None)
for key in [
    "fallback_used", "fallback_reason", "static_confidence", "model_used",
    "raw_response", "contract", "function", "swc_id", "fix_verified", "verification_status",
    "static_evidence", "retrieved_knowledge", "rag_similarity_score", "rag_explanation",
    "finding_hash", "compiler_verification"
]:
    schema["properties"].pop(key, None)
    if key in schema.get("required", []):
        schema["required"].remove(key)

print("Properties in schema:", list(schema["properties"].keys()))
print("Required:", schema.get("required", []))
print("Schema size in chars:", len(json.dumps(schema)))
