import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from auth import verify_token, require_scope, require_role
from db import devices, policies, compliance
from models import Policy, Device, ComplianceReport
from graph import set_device_compliance

app = FastAPI(title="Himmelblau Linux MDM API")

@app.get("/health")
def health():
    return {"ok": True}

# --- Policy endpoints (admin) ---

@app.get("/policy", dependencies=[Depends(require_scope("Policy.Read.All"))])
def list_policies(claims = Depends(verify_token)):
    tid = claims["tid"]
    items = list(policies.query_items(
        query="SELECT * FROM c WHERE c.tenantId=@t",
        parameters=[{"name":"@t","value":tid}],
        enable_cross_partition_query=True
    ))
    return {"items": items}

@app.put("/policy/{policy_id}", dependencies=[Depends(require_scope("Policy.ReadWrite.All"))])
def upsert_policy(policy_id: str, model: Policy, claims = Depends(verify_token)):
    if model.id != policy_id:
        raise HTTPException(400, "id mismatch")
    if model.tenantId != claims["tid"]:
        raise HTTPException(403, "wrong tenant")
    policies.upsert_item(model.dict())
    return {"ok": True}

# --- Device endpoints ---

@app.get("/devices", dependencies=[Depends(require_scope("Policy.Read.All"))])
def list_devices(claims = Depends(verify_token)):
    tid = claims["tid"]
    items = list(devices.query_items(
        query="SELECT * FROM c WHERE c.tenantId=@t",
        parameters=[{"name":"@t","value":tid}],
        enable_cross_partition_query=True
    ))
    return {"items": items}

@app.post("/devices/register")
def register_device(dev: Device, claims = Depends(verify_token)):
    # allow either user or admin token, just tenant-bound
    if dev.tenantId != claims["tid"]:
        raise HTTPException(403, "wrong tenant")
    devices.upsert_item(dev.dict())
    return {"ok": True}

# --- Compliance report from agents ---

@app.post("/compliance")
def post_compliance(report: ComplianceReport, claims = Depends(verify_token)):
    if report.tenantId != claims["tid"]:
        raise HTTPException(403, "wrong tenant")
    compliance.upsert_item(report.dict())
    # OPTIONAL: inform AAD (device_id here is your AAD device id if you have it)
    # set_device_compliance(device_id=report.deviceId, is_compliant=report.compliant)
    return {"ok": True}

# --- Device policy fetch (agents) ---

@app.get("/policy/effective/{device_id}")
def get_effective_policy(device_id: str, claims = Depends(verify_token)):
    tid = claims["tid"]
    # Simple: return latest policies for the tenant (you’ll add assignment logic later)
    rows = list(policies.query_items(
        query="SELECT * FROM c WHERE c.tenantId=@t",
        parameters=[{"name":"@t","value":tid}],
        enable_cross_partition_query=True
    ))
    # Merge strategy here can be enhanced (rings, assignments, tags, etc.)
    return {"deviceId": device_id, "tenantId": tid, "policies": rows}
