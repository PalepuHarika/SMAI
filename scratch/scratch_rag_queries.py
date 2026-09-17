import json
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.core.finding import StaticFinding, CodeContext

kb = SecurityKnowledgeBase()
retriever = RAGRetriever(kb)

def test_query(category, message, snippet):
    finding = StaticFinding(
        id="finding1",
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
        message=message,
        snippet=snippet
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
    results = retriever.retrieve(finding, context, top_k=3)
    return [r['category'] for r in results]

print("SWC-107 Reentrancy:", test_query("reentrancy", "Reentrancy detected", "msg.sender.call"))
print("SWC-104 Unchecked Call:", test_query("unchecked-call", "Unchecked return value", "msg.sender.call"))
print("SWC-115 tx.origin:", test_query("tx-origin", "tx.origin used", "tx.origin"))
print("SWC-116 Timestamp:", test_query("timestamp-dependence", "block.timestamp used", "block.timestamp"))
print("SWC-106 Selfdestruct:", test_query("unprotected-selfdestruct", "selfdestruct without auth", "selfdestruct"))
print("SWC-112 Delegatecall:", test_query("dangerous-delegatecall", "delegatecall to untrusted", "delegatecall"))
print("SWC-109 Uninitialized Storage:", test_query("uninitialized-storage", "uninitialized storage", "struct a"))
print("SWC-136 Missing Zero Address:", test_query("missing-zero-check", "missing zero address", "address(0)"))
print("SWC-105 Access Control:", test_query("missing-access-control", "missing access control", "public"))
print("SWC-103 Floating Pragma:", test_query("floating-pragma", "floating pragma", "^0.8.0"))
print("SWC-117 ecrecover:", test_query("ecrecover-validation", "ecrecover without check", "ecrecover"))
print("SWC-101 Integer Overflow:", test_query("integer-overflow", "integer overflow", "a + b"))

print("\nSemantic Retrieval Tests (without category match):")
print("1. external call occurs before balance update:", test_query("UNKNOWN", "external call occurs before balance update", ""))
print("2. return value from low-level call is ignored:", test_query("UNKNOWN", "return value from low-level call is ignored", ""))
print("3. authentication uses tx.origin:", test_query("UNKNOWN", "authentication uses tx.origin", ""))
print("4. block.timestamp is used for randomness:", test_query("UNKNOWN", "block.timestamp is used for randomness", ""))
print("5. delegatecall target controlled by user:", test_query("UNKNOWN", "delegatecall target controlled by user", ""))
print("6. owner address can be set to zero:", test_query("UNKNOWN", "owner address can be set to zero", ""))
print("7. unchecked arithmetic in Solidity 0.7:", test_query("UNKNOWN", "unchecked arithmetic in Solidity 0.7", ""))
print("8. ecrecover result is not checked for zero:", test_query("UNKNOWN", "ecrecover result is not checked for zero", ""))

print("\nNegative Retrieval Tests:")
print("1. ERC20 token transfer:", test_query("UNKNOWN", "ERC20 token transfer", ""))
print("2. constructor:", test_query("UNKNOWN", "constructor", ""))
print("3. event emission:", test_query("UNKNOWN", "event emission", ""))
print("4. safe arithmetic in Solidity 0.8:", test_query("UNKNOWN", "safe arithmetic in Solidity 0.8", ""))
print("5. normal deadline check:", test_query("UNKNOWN", "normal deadline check", ""))
print("6. safe onlyOwner function:", test_query("UNKNOWN", "safe onlyOwner function", ""))

print("\nAdversarial Retrieval Tests:")
print("1. Reentrancy vs unchecked call:", test_query("UNKNOWN", "msg.sender.call is unchecked", "msg.sender.call"))
print("2. Unchecked call vs delegatecall:", test_query("UNKNOWN", "delegatecall is unchecked", "target.delegatecall"))
print("3. Timestamp vs overflow:", test_query("UNKNOWN", "block.timestamp + 100", "block.timestamp + 100"))
print("4. tx.origin vs access control:", test_query("UNKNOWN", "tx.origin used for access control", "require(tx.origin == owner)"))
print("5. selfdestruct vs delegatecall:", test_query("UNKNOWN", "delegatecall to selfdestruct", "target.delegatecall"))
print("6. zero address vs access control:", test_query("UNKNOWN", "owner is zero address", "require(owner != address(0))"))
print("7. ecrecover vs tx.origin:", test_query("UNKNOWN", "ecrecover signer is tx.origin", "ecrecover"))
print("8. overflow vs unchecked call:", test_query("UNKNOWN", "unchecked block used for call", "unchecked"))
