import json
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.core.finding import StaticFinding, CodeContext

kb = SecurityKnowledgeBase()
retriever = RAGRetriever(kb)

queries = [
    # A. Exact SWC queries
    ("SWC-107", "reentrancy", "external call occurs before state update", "msg.sender.call"),
    ("SWC-104", "unchecked-call", "return value of call is not checked", "msg.sender.call"),
    ("SWC-115", "tx-origin", "tx.origin used for authentication", "require(tx.origin == owner)"),
    ("SWC-116", "timestamp-dependence", "block.timestamp used for randomness", "uint(block.timestamp)"),
    ("SWC-106", "unprotected-selfdestruct", "selfdestruct called without authorization", "selfdestruct(msg.sender)"),
    ("SWC-112", "dangerous-delegatecall", "delegatecall to untrusted address", "target.delegatecall(data)"),
    ("SWC-136", "missing-zero-check", "missing zero address validation", "require(owner != address(0))"),
    ("SWC-105", "missing-access-control", "missing access control on critical function", "function setOwner(address newOwner) public {"),
    ("SWC-103", "floating-pragma", "floating pragma", "pragma solidity ^0.8.0;"),
    ("SWC-117", "ecrecover-validation", "ecrecover without check", "ecrecover(hash, v, r, s)"),
    ("SWC-101", "integer-overflow", "integer overflow", "balances[msg.sender] += amount"),

    # B. Semantic queries (Empty category to test text retrieval)
    ("SWC-107", "", "external call before balance update", "msg.sender.call"),
    ("SWC-104", "", "unchecked low level call", "msg.sender.send"),
    ("SWC-115", "", "authentication uses transaction origin", "tx.origin"),
    ("SWC-116", "", "timestamp used as randomness", "block.timestamp"),
    ("SWC-112", "", "untrusted delegatecall", "delegatecall"),
    ("SWC-136", "", "owner set to zero", "address(0)"),
    ("SWC-103", "", "floating compiler version", "pragma"),
    ("SWC-117", "", "ecrecover zero validation", "ecrecover"),
    ("SWC-101", "", "arithmetic overflow", "+="),
]

top1_acc = 0
top3_rec = 0
top5_rec = 0

print(f"{'Query':<50} | {'Expected':<10} | {'Top-1':<10} | {'Top-3':<5} | {'Top-5':<5} | {'Similarity'}")
print("-" * 110)

for expected_swc, category, msg, snip in queries:
    finding = StaticFinding(
        id="f1",
        category=category,
        swc_id="",
        severity="High",
        confidence=0.9,
        contract="Test",
        file_path="test.sol",
        line_start=1,
        line_end=1,
        line_numbers=[1],
        function="test",
        message=msg,
        snippet=snip
    )
    context = CodeContext(
        file_path="test.sol",
        contract_name="Test",
        function_name="test",
        function_source="function test() {}",
        line_start=1,
        line_end=1,
        modifiers=[],
        state_variables=[],
        full_source=""
    )
    results = retriever.retrieve(finding, context, top_k=5)
    
    retrieved_swcs = [r.get("id") for r in results]
    top1 = retrieved_swcs[0] if retrieved_swcs else None
    
    is_top1 = top1 == expected_swc
    is_top3 = expected_swc in retrieved_swcs[:3]
    is_top5 = expected_swc in retrieved_swcs[:5]
    
    if is_top1: top1_acc += 1
    if is_top3: top3_rec += 1
    if is_top5: top5_rec += 1
    
    sim = results[0].get("similarity_score") if results else 0.0
    query_name = category if category else msg
    print(f"{query_name[:48]:<50} | {expected_swc:<10} | {str(top1):<10} | {str(is_top3):<5} | {str(is_top5):<5} | {sim:.2f}")

print("\n--- METRICS ---")
print(f"Total Queries: {len(queries)}")
print(f"Top-1 Accuracy: {top1_acc / len(queries):.2f}")
print(f"Top-3 Recall:   {top3_rec / len(queries):.2f}")
print(f"Top-5 Recall:   {top5_rec / len(queries):.2f}")
