import os
from typing import List, Dict, Any, Tuple, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.core.finding import StaticFinding, CodeContext

class RAGRetriever:
    """
    Retrieves the most relevant vulnerability descriptions, attack patterns, and mitigations
    for a given static finding and code context.
    """

    def __init__(self, knowledge_base: SecurityKnowledgeBase):
        self.kb = knowledge_base
        self.entries = self.kb.get_all()
        self.vectorizer = TfidfVectorizer(stop_words='english')
        
        # Build search corpus from descriptions, exploit patterns, and mitigation
        self.corpus = []
        for entry in self.entries:
            text = f"{entry.get('name', '')} {entry.get('category', '')} {entry.get('description', '')} {entry.get('exploit_pattern', '')} {entry.get('mitigation', '')}"
            self.corpus.append(text)
        
        if self.corpus:
            self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus)
        else:
            self.tfidf_matrix = None

    def _normalize_solidity(self, text: str) -> str:
        import re
        # Remove single-line comments
        text = re.sub(r'//.*', '', text)
        # Remove multi-line comments
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        # Remove string literals
        text = re.sub(r'".*?"|\'.*?\'', '""', text)
        return text

    def retrieve(self, finding: StaticFinding, context: CodeContext, top_k: int = 2) -> List[Dict[str, Any]]:
        query_parts = [
            finding.category,
            finding.swc_id or '',
            finding.message,
            context.function_name,
            finding.snippet or '',
            ' '.join(context.modifiers),
            ' '.join(context.state_variables[:3])
        ]
        query_text = ' '.join(p for p in query_parts if p).strip()
        query_text = self._normalize_solidity(query_text)

        import numpy as np
        similarities = np.zeros(len(self.entries))
        if self.tfidf_matrix is not None and query_text:
            query_vec = self.vectorizer.transform([query_text])
            similarities = cosine_similarity(query_vec, self.tfidf_matrix)[0]

        results = []
        seen_ids = set()

        # 1. First priority: Exact category match
        direct_match = self.kb.get_by_category(finding.category)
        if direct_match:
            item = dict(direct_match)
            # Find cosine similarity for direct match
            try:
                d_idx = next(i for i, e in enumerate(self.entries) if e.get('category') == finding.category)
                score = float(similarities[d_idx])
            except (StopIteration, IndexError):
                score = 0.85
            item['similarity_score'] = round(max(0.70, score), 4)
            item['relevance_reason'] = (
                f"Direct category match for {item.get('id', '')} ({item.get('name', '')}) "
                f"matching static detector '{finding.category}' in '{context.function_name}'."
            )
            results.append(item)
            seen_ids.add(item.get('id', item.get('category')))

        # 2. Vector search ranked by cosine similarity
        if self.tfidf_matrix is not None:
            ranked_indices = similarities.argsort()[::-1]
            for idx in ranked_indices:
                entry = self.entries[idx]
                e_id = entry.get('id', entry.get('category'))
                score = float(similarities[idx])
                if e_id not in seen_ids and score > 0.05:
                    item = dict(entry)
                    item['similarity_score'] = round(score, 4)
                    item['relevance_reason'] = (
                        f"Textual similarity ({score:.2f}) to source code and static message in function '{context.function_name}'."
                    )
                    results.append(item)
                    seen_ids.add(e_id)
                if len(results) >= top_k:
                    break

        return results[:top_k]

    @staticmethod
    def format_kb_context_for_llm(results: List[Dict[str, Any]]) -> str:
        if not results:
            return "No external RAG security knowledge retrieved."

        blocks = []
        for idx, r in enumerate(results, 1):
            block = (
                f"--- Knowledge Reference #{idx} [{r.get('id', 'SWC')} - {r.get('name', 'Vulnerability')}] ---\n"
                f"Relevance Reason: {r.get('relevance_reason', 'Domain knowledge match')}\n"
                f"Similarity Score: {r.get('similarity_score', 'N/A')}\n"
                f"Description: {r.get('description', '')}\n"
                f"Exploit Pattern: {r.get('exploit_pattern', '')}\n"
                f"Mitigation & Secure Patterns: {r.get('mitigation', '')}"
            )
            blocks.append(block)
        return "\n\n".join(blocks)

    @staticmethod
    def get_explainability_summary(results: List[Dict[str, Any]]) -> Tuple[Optional[float], Optional[str]]:
        if not results:
            return None, None
        top_score = results[0].get('similarity_score', 0.0)
        reasons = [f"[{r.get('id', '')}]: {r.get('relevance_reason', '')}" for r in results]
        return top_score, " | ".join(reasons)
