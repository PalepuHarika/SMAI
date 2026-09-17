import asyncio
import time
from backend.pipeline import SecurityPipeline
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.rag.retriever import RAGRetriever
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.llm.reasoner import LLMReasoner
from unittest.mock import patch, AsyncMock, MagicMock

async def main():
    analyzer = SolidityStaticAnalyzer()
    kb = SecurityKnowledgeBase("backend/data/knowledge_base.json")
    retriever = RAGRetriever(knowledge_base=kb)
    reasoner = LLMReasoner()
    pipeline = SecurityPipeline(analyzer=analyzer, retriever=retriever, reasoner=reasoner)
    
    async def mock_post(*args, **kwargs):
        await asyncio.sleep(0.01)
        mock_response = MagicMock()
        mock_response.json.return_value = {"message": {"content": '{"is_vulnerable": true, "confidence": 0.9}'}}
        mock_response.raise_for_status = MagicMock()
        return mock_response
    
    with patch.object(reasoner.client, 'post', new_callable=AsyncMock) as mock_post_method:
        mock_post_method.side_effect = mock_post
        
        base_code = """
pragma solidity ^0.8.0;
contract BaseVuln {
    mapping(address => uint) balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        msg.sender.call{value: bal}("");
        balances[msg.sender] = 0;
    }
}
"""
        # Small contract
        t0 = time.time()
        await pipeline.scan(base_code, "Small.sol")
        small_time = time.time() - t0
        
        # Medium contract (10 repeated vulnerabilities)
        medium_code = base_code * 10
        t0 = time.time()
        await pipeline.scan(medium_code, "Medium.sol")
        med_time = time.time() - t0
        
        # Large contract (50 repeated vulnerabilities)
        large_code = base_code * 50
        t0 = time.time()
        await pipeline.scan(large_code, "Large.sol")
        large_time = time.time() - t0
        
        print(f"Small (1 vuln) time:  {small_time:.3f}s")
        print(f"Medium (10 vulns) time: {med_time:.3f}s")
        print(f"Large (50 vulns) time: {large_time:.3f}s")

if __name__ == "__main__":
    asyncio.run(main())
