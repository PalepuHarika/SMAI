import os
import json
from backend.rag.knowledge_base import SecurityKnowledgeBase

# Test malformed JSON
temp_path = "temp_malformed.json"
with open(temp_path, "w") as f:
    f.write("{ malformed }")

try:
    kb = SecurityKnowledgeBase(json_path=temp_path)
    print("Malformed JSON: Handled")
except Exception as e:
    print(f"Malformed JSON: Crash - {type(e).__name__}: {e}")

# Test missing file
kb = SecurityKnowledgeBase(json_path="nonexistent.json")
print("Missing file: Handled. Entries count:", len(kb.entries))
