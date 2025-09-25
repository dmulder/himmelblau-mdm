from typing import List, Optional, Dict
from pydantic import BaseModel

class Policy(BaseModel):
    id: str
    tenantId: str
    name: str
    version: int
    data: Dict  # your intune-spec JSON blob
    assignments: Dict = {}

class Device(BaseModel):
    id: str
    tenantId: str
    userObjectId: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    tags: List[str] = []

class ComplianceReport(BaseModel):
    deviceId: str
    tenantId: str
    compliant: bool
    reasons: List[str] = []
    details: Dict = {}
