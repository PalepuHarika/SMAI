import pytest
import uuid
import asyncio
_run = uuid.uuid4().hex[:8]
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.db.database import init_db

@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()

@pytest.mark.asyncio
async def test_full_auth_and_rbac_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register User A
        res_a = await client.post("/auth/register", json={
            "email": f"alice_{_run}@example.com",
            "password": "alicePassword123!",
            "role": "USER"
        })
        assert res_a.status_code == 201
        headers_a = {"Authorization": f"Bearer {res_a.json()['access_token']}"}

        # 2. Register User B
        res_b = await client.post("/auth/register", json={
            "email": f"bob_{_run}@example.com",
            "password": "bobPassword123!",
            "role": "USER"
        })
        assert res_b.status_code == 201
        headers_b = {"Authorization": f"Bearer {res_b.json()['access_token']}"}

        # 3. Register Admin User
        res_admin = await client.post("/auth/register", json={
            "email": f"admin_{_run}@example.com",
            "password": "adminPassword123!",
            "role": "ADMIN"
        })
        assert res_admin.status_code == 201
        headers_admin = {"Authorization": f"Bearer {res_admin.json()['access_token']}"}

        # 5. User A creates an analysis
        with open('/home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner/contracts/ReentrancyVault.sol') as f:
            sol_src = f.read()

        scan_res = await client.post("/api/analysis", json={
            "contract_name": "ReentrancyVault.sol",
            "source_code": sol_src
        }, headers=headers_a)
        assert scan_res.status_code == 202
        scan_data = scan_res.json()
        analysis_id = scan_data["analysis_id"]

        # Polling for completion
        for _ in range(10):
            res_poll = await client.get(f"/api/analysis/{analysis_id}", headers=headers_a)
            if res_poll.json().get("status") != "PENDING":
                break
            await asyncio.sleep(0.5)

        res_final = await client.get(f"/api/analysis/{analysis_id}", headers=headers_a)
        assert res_final.status_code == 200
        assert res_final.json().get("is_vulnerable") is True

        # 6. User A checks history
        hist_a = await client.get("/api/analysis/history", headers=headers_a)
        assert hist_a.status_code == 200
        assert len(hist_a.json()) >= 1

        # 7. User B tries to access User A's analysis -> 403 Forbidden
        res_forbidden = await client.get(f"/api/analysis/{analysis_id}", headers=headers_b)
        assert res_forbidden.status_code == 403

        # 8. User A tries to access admin analytics -> 403 Forbidden
        admin_forbidden = await client.get("/api/admin/analytics", headers=headers_a)
        assert admin_forbidden.status_code == 403

        # 9. Admin accesses User A's analysis -> 200 OK
        admin_scan_view = await client.get(f"/api/analysis/{analysis_id}", headers=headers_admin)
        assert admin_scan_view.status_code == 200

        # 10. Admin accesses system analytics -> 200 OK
        analytics_res = await client.get("/api/admin/analytics", headers=headers_admin)
        assert analytics_res.status_code == 200
