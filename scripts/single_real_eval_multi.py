import asyncio
import time
import httpx
from backend.pipeline import SecurityPipeline
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.analyzer.code_extractor import CodeContextExtractor
from backend.rag.retriever import RAGRetriever
from backend.rag.knowledge_base import SecurityKnowledgeBase

async def main():
    pipeline = SecurityPipeline()
    pipeline.reasoner.client.timeout = httpx.Timeout(1200.0)
    
    analyzer = SolidityStaticAnalyzer()
    extractor = CodeContextExtractor()
    kb = SecurityKnowledgeBase()
    retriever = RAGRetriever(kb)
    
    code = """pragma solidity ^0.8.0;

contract MultiVuln {
    mapping(address => uint) balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdrawAll() public {
        // SWC-115: tx.origin authorization
        require(tx.origin == owner);
        
        uint bal = balances[msg.sender];
        
        // SWC-107: Reentrancy
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        
        balances[msg.sender] = 0;
    }
}"""
    
    print("--- RUNNING STATIC ANALYZER ---")
    static_findings = analyzer.analyze(code, "MultiVuln.sol")
    for f in static_findings:
        print(f"Static Finding: {f.category} | SWC: {f.swc_id} | Severity: {f.severity}")
        context = extractor.extract(code, f)
        rag_docs = retriever.retrieve(f, context, top_k=1)
        if rag_docs:
            print(f"  RAG Evidence: {rag_docs[0]['name']} (Similarity: {rag_docs[0].get('similarity_score', 0):.2f})")
            
    print("\n--- RUNNING REAL LLM E2E PIPELINE (MULTI-FINDING) ---")
    t0 = time.time()
    try:
        report = await pipeline.scan(code, "MultiVuln.sol", mode="C")
        t1 = time.time()
        
        print("\n--- RESULTS ---")
        print(f"Total Execution Time: {t1-t0:.2f}s")
        print(f"Security Score: {report.security_score}")
        print(f"Final Risk: {report.risk_level}")
        print("Findings:")
        for f in report.findings:
            print(f"\n  Vulnerability: {f.vulnerability}")
            print(f"  SWC ID: {f.swc_id}")
            print(f"  Severity: {f.severity}")
            print(f"  Verification Status: {f.verification_status}")
            print(f"  LLM Explanation: {f.explanation}")
            print(f"  Final Confidence: {f.confidence}")
    except Exception as e:
        print(f"\n--- TIMEOUT / ERROR ---")
        print(f"Total Execution Time: {time.time()-t0:.2f}s")
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
