import time, json, httpx, jwt, os
from fastapi import HTTPException, Depends, Header
from functools import lru_cache

TENANT_ID = os.environ["HB_TENANT_ID"]
ALLOWED_AUD = os.environ["HB_ALLOWED_AUDIENCE"]
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

@lru_cache(maxsize=1)
def _jwks():
    with httpx.Client(timeout=10) as c:
        return c.get(JWKS_URL).json()

def _get_key(kid):
    for k in _jwks().get("keys", []):
        if k["kid"] == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
    raise HTTPException(status_code=401, detail="Signing key not found")

def verify_token(auth_header: str = Header(..., alias="Authorization")):
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth_header.split(" ", 1)[1]
    try:
        unv = jwt.get_unverified_header(token)
        key = _get_key(unv["kid"])
        claims = jwt.decode(
            token, key=key, algorithms=["RS256"],
            audience=ALLOWED_AUD, options={"leeway": 60}
        )
        # Basic freshness
        if claims.get("exp", 0) < time.time() - 60:
            raise HTTPException(status_code=401, detail="Token expired")
        return claims
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

def require_role(*allowed_roles):
    def _checker(claims = Depends(verify_token)):
        roles = claims.get("roles", []) or claims.get("scp", "").split()
        if any(r in roles for r in allowed_roles) or "Policy.ReadWrite.All" in roles:
            return claims
        raise HTTPException(status_code=403, detail="Insufficient role")
    return _checker

def require_scope(scope):
    def _checker(claims = Depends(verify_token)):
        scopes = claims.get("scp", "")
        if scope in scopes.split():
            return claims
        # roles can also imply write
        roles = claims.get("roles", [])
        if scope.endswith("Read.All") and ("Policy.ReadWrite.All" in roles or "MDM.Admin" in roles):
            return claims
        raise HTTPException(status_code=403, detail="Missing scope")
    return _checker
