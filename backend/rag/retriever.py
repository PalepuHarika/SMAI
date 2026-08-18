import os
from typing import List, Dict, Any, Tuple
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

    def retrieve(self, finding: StaticFinding, context: CodeContext, top_k: int = 2) -> List[Dict[str, Any]]:
        # 1. First priority: Exact category match
        direct_match = self.kb.get_by_category(finding.category)
        
        # 2. Vector search query
        query_text = f"{finding.category} {finding.message} {context.function_name} {context.function_source}"
        
        results = []
        if direct_match:
            results.append(direct_match)

        if self.tfidf_matrix is not None:
            query_vec = self.vectorizer.transform([query_text])
            similarities = cosine_similarity(query_vec, self.tfidf_matrix)[0]
            ranked_indices = similarities.argsort()[::-1]

            for idx in ranked_indices:
                entry = self.entries[idx]
                if entry not in results and similarities[idx] > 0.05:
                    results.append(entry)
                if len(results) >= top_k:
                    break

        return results[:top_k]
