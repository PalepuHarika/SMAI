import os
import json
from typing import List, Dict, Any, Optional

class SecurityKnowledgeBase:
    """
    Manages the security knowledge base containing SWC registries, CWE mappings,
    vulnerability patterns, attack scenarios, and mitigations.
    """

    def __init__(self, json_path: Optional[str] = None):
        if not json_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            json_path = os.path.join(base_dir, 'data', 'knowledge_base.json')
        
        self.json_path = json_path
        self.entries: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        if os.path.exists(self.json_path):
            try:
                with open(self.json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.entries = [d for d in data if isinstance(d, dict) and "id" in d and "category" in d]
                    else:
                        print("Error: Knowledge base JSON root must be a list.")
                        self.entries = []
            except json.JSONDecodeError as e:
                print(f"Error loading knowledge base: Malformed JSON. {e}")
                self.entries = []
            except Exception as e:
                print(f"Error loading knowledge base: {e}")
                self.entries = []
        else:
            self.entries = []

    def get_by_category(self, category: str) -> Optional[Dict[str, Any]]:
        for entry in self.entries:
            if entry.get('category') == category:
                return entry
        return None

    def get_all(self) -> List[Dict[str, Any]]:
        return self.entries
