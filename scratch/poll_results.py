import asyncio, httpx, json

async def check():
    async with httpx.AsyncClient() as c:
        r = await c.post('http://localhost:8001/auth/register', json={'email':'poll2@test.com','password':'pass12345'})
        if r.status_code == 400:
            r = await c.post('http://localhost:8001/auth/login', json={'email':'poll2@test.com','password':'pass12345'})
        tok = r.json()['access_token']
        h = {'Authorization': 'Bearer ' + tok}
        for aid in ['analysis-9c1ea00c97e7', 'analysis-f31e277123c4', 'analysis-e7248e9b8be9']:
            p = await c.get('http://localhost:8001/api/analysis/' + aid, headers=h, timeout=10)
            d = p.json()
            s = d.get('status', 'COMPLETED')
            findings = d.get('findings', [])
            score = d.get('security_score')
            risk = d.get('risk_level')
            print(aid + ': status=' + str(s) + ' findings=' + str(len(findings)) + ' score=' + str(score) + ' risk=' + str(risk))
            for f in findings:
                vuln = f.get('vulnerability', '')
                swc = f.get('swc_id', '')
                sev = f.get('severity', '')
                is_v = f.get('is_vulnerable', '')
                vs = f.get('verification_status', '')
                conf = f.get('confidence', 0)
                fb = f.get('fallback_used', '')
                model = f.get('model_used', '')
                rag = len(f.get('retrieved_knowledge') or [])
                print('  [' + vuln + '] SWC=' + str(swc) + ' sev=' + sev + ' vuln=' + str(is_v) + ' vstatus=' + vs + ' conf=' + str(conf) + ' fallback=' + str(fb) + ' rag_entries=' + str(rag) + ' model=' + str(model))

asyncio.run(check())
