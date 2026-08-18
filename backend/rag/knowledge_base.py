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
            with open(self.json_path, 'r', encoding='utf-8') as f:
                self.entries = json.load(f)
        else:
            self.entries = []

    def get_by_category(self, category: str) -> Optional[Dict[str, Any]]:
        for entry in self.entries:
            if entry.get('category') == category:
                return entry
        return None

    def get_all(self) -> List[Dict[str, Any]]:
        return self.entries
