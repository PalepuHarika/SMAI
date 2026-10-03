import asyncio
import httpx

async def test_ollama():
    client = httpx.AsyncClient(
        base_url="http://localhost:11434",
        timeout=httpx.Timeout(30.0, connect=10.0)
    )
    
    try:
        payload = {
            "model": "qwen2.5-coder:latest",
            "messages": [{"role": "user", "content": "test"}],
            "stream": False,
            "options": {"num_predict": 10}
        }
        response = await client.post("/api/chat", json=payload)
        response.raise_for_status()
        result = response.json()
        print("Ollama SUCCESS:", result.get("message", {}).get("content", "")[:100])
    except Exception as e:
        print(f"Ollama ERROR: {e}")
    finally:
        await client.aclose()

if __name__ == "__main__":
    asyncio.run(test_ollama())
