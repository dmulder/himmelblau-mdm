import os, httpx, time, base64, json

TENANT_ID = os.environ["HB_TENANT_ID"]
CLIENT_ID = os.environ["HB_CLIENT_ID"]
CLIENT_SECRET = os.environ["HB_CLIENT_SECRET"]

def _get_app_token(scope="https://graph.microsoft.com/.default"):
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials", "scope": scope
    }
    with httpx.Client(timeout=10) as c:
        r = c.post(url, data=data)
        r.raise_for_status()
        return r.json()["access_token"]

def set_device_compliance(device_id: str, is_compliant: bool, is_managed: bool=True):
    # NOTE: use /beta or v1.0 endpoints as appropriate; this is a placeholder
    token = _get_app_token()
    url = f"https://graph.microsoft.com/beta/devices/{device_id}"
    payload = {"isCompliant": is_compliant, "isManaged": is_managed}
    with httpx.Client(timeout=10) as c:
        r = c.patch(url, json=payload, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        return r.status_code
