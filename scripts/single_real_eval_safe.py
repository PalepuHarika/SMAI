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
    
    code = """pragma solidity 0.8.24;

contract SafeVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);

        balances[msg.sender] -= amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}"""
    
    print("--- RUNNING STATIC ANALYZER ---")
    static_findings = analyzer.analyze(code, "SafeVault.sol")
    for f in static_findings:
        print(f"Static Finding: {f.category} | SWC: {f.swc_id} | Severity: {f.severity}")
        context = extractor.extract(code, f)
        rag_docs = retriever.retrieve(f, context, top_k=2)
        print(f"RAG Evidence for {f.category}:")
        for doc in rag_docs:
            print(f"  - {doc['name']} (Similarity: {doc.get('similarity_score', 0):.2f})")
            
    print("\n--- RUNNING REAL LLM E2E PIPELINE ---")
    t0 = time.time()
    try:
        report = await pipeline.scan(code, "SafeVault.sol", mode="C")
        t1 = time.time()
        
        print("\n--- RESULTS ---")
        print(f"Total Execution Time: {t1-t0:.2f}s")
        print(f"Security Score: {report.security_score}")
        print(f"Final Risk: {report.risk_level}")
        print("Findings:")
        if not report.findings:
            print("  No final findings (all flagged issues safely dismissed or none detected).")
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
