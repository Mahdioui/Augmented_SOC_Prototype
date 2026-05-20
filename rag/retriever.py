"""
retriever.py
------------
Keyword-based retrieval over synthetic knowledge base.
"""

from __future__ import annotations

from typing import Dict, List

from rag.knowledge_base import load_knowledge_base


def retrieve_documents(query: str, top_k: int = 3) -> List[Dict[str, str]]:
    kb = load_knowledge_base()
    query_terms = set(query.lower().split())
    scored = []
    for doc in kb:
        text = f"{doc['title']} {doc['content']}".lower()
        score = sum(1 for term in query_terms if term in text)
        scored.append((score, doc))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [doc for score, doc in scored if score > 0][:top_k]
