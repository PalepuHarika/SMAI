import asyncio
from backend.pipeline import SecurityPipeline

async def test_direct():
    with open("contracts/ReentrancyVault.sol", "r") as f:
        code = f.read()
        
    pipeline = SecurityPipeline()
    try:
        report = await pipeline.scan(code, "ReentrancyVault.sol", "C")
        print("Success:", report)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_direct())
