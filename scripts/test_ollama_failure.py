import asyncio
import time
from backend.pipeline import SecurityPipeline
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.rag.retriever import RAGRetriever
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.llm.reasoner import LLMReasoner

async def main():
    print("Testing backend connectivity to unavailable Ollama...")
    analyzer = SolidityStaticAnalyzer()
    kb = SecurityKnowledgeBase("backend/data/knowledge_base.json")
    retriever = RAGRetriever(knowledge_base=kb)
    
    # Intentionally use localhost:11434 which is proven to be down
    reasoner = LLMReasoner(ollama_url="http://localhost:11434", model="qwen2.5-coder:latest")
    # Speed up timeout for the test
    reasoner.client.timeout = 2.0
    
    pipeline = SecurityPipeline(analyzer=analyzer, retriever=retriever, reasoner=reasoner)
    
    code = """
pragma solidity ^0.8.0;
contract Test {
    mapping(address => uint) balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        msg.sender.call{value: bal}("");
        balances[msg.sender] = 0;
    }
}
"""
    t0 = time.time()
    report = await pipeline.scan(code, "Test.sol")
    t1 = time.time()
    
    print(f"Scan completed in {t1 - t0:.2f}s")
    for f in report.findings:
        print(f"Finding: {f.vulnerability}")
        print(f"Status: {f.verification_status}")
        print(f"Confidence: {f.confidence}")
        
    print(f"Score: {report.security_score}")
    print(f"Risk: {report.risk_level}")

if __name__ == "__main__":
    asyncio.run(main())
