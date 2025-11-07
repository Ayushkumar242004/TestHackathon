# backend/app/main.py
import os
import time
import tempfile
from typing import Optional
from fastapi import Header
from typing import Literal
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

# relative imports so this module is importable when run from backend/ folder
from .settings import settings
from .crud import (
    init_db,
    create_inspection,
    create_certificate,
    get_inspection_by_content_hash,
    revoke_certificate as crud_revoke_certificate,
    mark_certificate_revoked,
)
from .pinata import pin_file, pin_json
from .blockchain import (
    build_inspection_raw_hash,
    get_chain_id,
    record_inspection_with_signature,
    issue_certificate,
    revoke_certificate,
    recover_signer_from_raw,
    w3,
)
from .schemas import UploadResponse, SignPayload, SubmitInspectionIn, IssueCertificateIn
from .tasks import scheduler

app = FastAPI(title="Compliance Platform Backend")


@app.on_event("startup")
def startup():
    # initialize the DB and start any background schedulers
    init_db()
    try:
        scheduler.start()
    except Exception:
        # scheduler may already be running in dev reload; ignore startup errors
        pass


@app.on_event("shutdown")
def shutdown():
    try:
        scheduler.shutdown(wait=False)
    except Exception:
        pass


@app.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """
    Accepts a file upload, writes it to a temporary file, pins to Pinata,
    and returns ipfs CID and solidity keccak content hash.
    """
    # use platform temp dir
    tmp_dir = tempfile.gettempdir()
    timestamp = int(time.time())
    safe_name = f"{timestamp}_{os.path.basename(file.filename)}"
    temp_path = os.path.join(tmp_dir, safe_name)

    # write file content to temp path
    content = await file.read()
    try:
        with open(temp_path, "wb") as f:
            f.write(content)

        # pin via pinata helper
        try:
            res = pin_file(temp_path, metadata={"name": file.filename})
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Pinata error: {e}")

        cid = res.get("IpfsHash") or res.get("ipfsHash")
        if not cid:
            raise HTTPException(status_code=500, detail="Pinata did not return CID")

        ipfs_uri = f"ipfs://{cid}"
        content_hash_bytes = w3.keccak(text=ipfs_uri)
        content_hash_hex = content_hash_bytes.hex()

        return {"ipfs_cid": cid, "content_hash": content_hash_hex}

    finally:
        # best-effort cleanup of temp file
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass


@app.post("/sign-payload")
async def create_sign_payload(ipfs_cid: str, summary: Optional[str] = None):
    """
    Build a signing payload for an inspector to sign.
    Returns the payload (contract, chain_id, hashes, inspector address, timestamp, nonce).
    """
    content_hash = w3.keccak(text=f"ipfs://{ipfs_cid}").hex()
    summary_hash = w3.keccak(text=summary).hex() if summary else "0x" + "00" * 32
    inspector_timestamp = int(time.time())
    nonce = w3.keccak(text=str(time.time())).hex()

    inspector_address = None
    if getattr(settings, "INSPECTOR_PK", None):
        inspector_address = w3.eth.account.from_key(settings.INSPECTOR_PK).address

    payload = {
        "contract_address": settings.CONTRACT_ADDRESS,
        "chain_id": settings.CHAIN_ID,
        "content_hash": content_hash,
        "summary_hash": summary_hash,
        "inspector": inspector_address,
        "inspector_timestamp": inspector_timestamp,
        "nonce": nonce,
    }
    return payload


@app.post("/submit-inspection")
async def submit_inspection(payload: SubmitInspectionIn):
    """
    Verify inspector signature, submit the inspection on-chain, and store the record in DB.
    """
    # Build raw hash and recover signer
    raw = build_inspection_raw_hash(
        settings.CONTRACT_ADDRESS,
        settings.CHAIN_ID,
        payload.content_hash,
        payload.summary_hash or "0x" + "00" * 32,
        payload.inspector,
        payload.inspector_timestamp,
        payload.nonce,
    )
    recovered = recover_signer_from_raw(raw, payload.signature)
    if recovered.lower() != payload.inspector.lower():
        raise HTTPException(status_code=400, detail="Signature verification failed")

    # Send to chain
    try:
        receipt = record_inspection_with_signature(
            settings.SUBMITTER_PK,
            payload.content_hash,
            payload.summary_hash or "0x" + "00" * 32,
            payload.inspector,
            payload.inspector_timestamp,
            payload.nonce,
            payload.signature,
            payload.meta or b"",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"On-chain submit failed: {e}")

    # store in DB
    rec = {
        "content_hash": payload.content_hash,
        "summary_hash": payload.summary_hash,
        "ipfs_cid": None,
        "inspector": payload.inspector,
        "submitter": w3.eth.account.from_key(settings.SUBMITTER_PK).address,
        "inspector_timestamp": payload.inspector_timestamp,
        "nonce": payload.nonce,
        "signature": payload.signature,
        "onchain_tx": receipt.transactionHash.hex() if hasattr(receipt, "transactionHash") else str(receipt),
    }
    create_inspection(rec)
    return {"tx": receipt.transactionHash.hex() if hasattr(receipt, "transactionHash") else str(receipt)}

from hexbytes import HexBytes

@app.post("/issue-certificate")
def issue_certificate_endpoint(data: IssueCertificateIn):
    cert_hash_bytes = w3.keccak(text=data.cert_id)      # HexBytes (32 bytes)
    try:
        receipt = issue_certificate(settings.SUBMITTER_PK, cert_hash_bytes, data.owner, data.expiry or 0)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    cert_hash_hex = cert_hash_bytes.hex()
    obj = {
        "cert_hash": cert_hash_hex,
        "issuer": w3.eth.account.from_key(settings.SUBMITTER_PK).address,
        "owner": data.owner,
        "expiry": data.expiry,
        "revoked": False,
        "issued_at": int(time.time()),
        "tx_hash": receipt.transactionHash.hex() if hasattr(receipt, "transactionHash") else str(receipt),
    }
    create_certificate(obj)
    return {"tx": receipt.transactionHash.hex() if hasattr(receipt, "transactionHash") else str(receipt), "cert_hash": cert_hash_hex}


@app.post("/revoke-certificate")
def revoke_certificate_endpoint(cert_hash: str):
    """
    Revoke a previously issued certificate on chain and mark revoked in DB.
    """
    try:
        receipt = revoke_certificate(settings.SUBMITTER_PK, cert_hash)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        # update DB to reflect revocation
        mark_certificate_revoked(cert_hash)
    except Exception:
        # If DB update fails, do not mask the on-chain success; but log or notify in real app
        pass

    return {"tx": receipt.transactionHash.hex() if hasattr(receipt, "transactionHash") else str(receipt)}

@app.post("/debug-raw-hash")
def debug_raw_hash(data: dict):
    raw = build_inspection_raw_hash(
        settings.CONTRACT_ADDRESS,
        settings.CHAIN_ID,
        data["content_hash"],
        data["summary_hash"],
        data["inspector"],
        data["inspector_timestamp"],
        data["nonce"]
    )
    return {"raw_hash_hex": raw.hex()}


# ---------------------------
# Admin / Manager endpoints
# ---------------------------

def _require_admin(api_key: str | None):
    """
    Simple API-key check for admin actions.
    For production, replace with proper auth (JWT/OAuth).
    """
    if not api_key or api_key != getattr(settings, "ADMIN_API_KEY", None):
        raise HTTPException(status_code=401, detail="Missing or invalid admin API key")


@app.post("/admin/grant-role")
def api_grant_role(
    role: Literal["INSPECTOR_ROLE", "SUBMITTER_ROLE", "AGENT_ROLE", "ADMIN_ROLE"],
    target_address: str,
    x_admin_key: str | None = Header(None)
):
    """
    ADMIN only: grant a role to an address.
    Input JSON/body form:
      { "role": "INSPECTOR_ROLE", "target_address": "0x..." }

    Protected by header:
      X-Admin-Key: <ADMIN_API_KEY>
    """
    _require_admin(x_admin_key)
    try:
        tx_receipt = grant_role(settings.DEPLOYER_PK or settings.ADMIN_PK, role, target_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"grant_role failed: {e}")
    return {"tx": tx_receipt.transactionHash.hex() if hasattr(tx_receipt, "transactionHash") else str(tx_receipt)}


@app.post("/admin/revoke-role")
def api_revoke_role(
    role: Literal["INSPECTOR_ROLE", "SUBMITTER_ROLE", "AGENT_ROLE", "ADMIN_ROLE"],
    target_address: str,
    x_admin_key: str | None = Header(None)
):
    """
    ADMIN only: revoke a role from an address.
    Body:
      { "role": "INSPECTOR_ROLE", "target_address": "0x..." }
    Header:
      X-Admin-Key: <ADMIN_API_KEY>
    """
    _require_admin(x_admin_key)
    try:
        tx_receipt = revoke_role(settings.DEPLOYER_PK or settings.ADMIN_PK, role, target_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"revoke_role failed: {e}")
    return {"tx": tx_receipt.transactionHash.hex() if hasattr(tx_receipt, "transactionHash") else str(tx_receipt)}


# ---------------------------
# Role inspection / info
# ---------------------------

@app.get("/roles/{address}")
def get_roles_for_address(address: str):
    """
    Query which of the platform roles this address currently has on-chain.
    Returns JSON with booleans for each known role.
    """
    try:
        inspector = has_role("INSPECTOR_ROLE", address)
        submitter = has_role("SUBMITTER_ROLE", address)
        agent = has_role("AGENT_ROLE", address)
        admin = has_role("ADMIN_ROLE", address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"error checking roles: {e}")

    return {
        "address": address,
        "roles": {
            "INSPECTOR_ROLE": inspector,
            "SUBMITTER_ROLE": submitter,
            "AGENT_ROLE": agent,
            "ADMIN_ROLE": admin
        }
    }


# ---------------------------
# Auditor & Regulator endpoints
# ---------------------------

@app.get("/audit/verify-inspection")
def audit_verify_inspection(content_hash: str):
    """
    Verify an inspection:
      - check if seen on-chain mapping (contract)
      - fetch DB record if present
      - (optional) verify signature stored in DB against payload
    Input: query param content_hash (0x... or hex)
    Output: JSON with onchain: bool, db_record: {...} or null, signature_valid: bool or null
    """
    # normalize hex keys (allow with/without 0x)
    ch = content_hash
    if not ch.startswith("0x"):
        ch = "0x" + ch

    onchain = False
    try:
        onchain = check_inspection_onchain(ch)
    except Exception as e:
        # log or include error details
        raise HTTPException(status_code=500, detail=f"on-chain check failed: {e}")

    # look up DB record if exists
    db_rec = get_inspection_by_content_hash(ch)
    sig_ok = None
    if db_rec:
        # if we have signature and inspector fields, verify signature locally
        try:
            if getattr(db_rec, "signature", None):
                raw = build_inspection_raw_hash(
                    settings.CONTRACT_ADDRESS,
                    settings.CHAIN_ID,
                    db_rec.content_hash,
                    db_rec.summary_hash or "0x" + "00" * 32,
                    db_rec.inspector,
                    db_rec.inspector_timestamp,
                    db_rec.nonce,
                )
                recovered = recover_signer_from_raw(raw, db_rec.signature)
                sig_ok = (recovered.lower() == db_rec.inspector.lower())
            else:
                sig_ok = None
        except Exception:
            sig_ok = False

    return {"content_hash": ch, "onchain": onchain, "db_record": db_rec and dict(db_rec.__dict__) or None, "signature_valid": sig_ok}


@app.get("/audit/verify-certificate")
def audit_verify_certificate(cert_hash: str):
    """
    Verify a certificate's on-chain validity (calls contract view isCertificateValid(bytes32)).
    Input: cert_hash (0x-prefixed or plain hex)
    Output: { cert_hash, onchain_valid: true/false, db_record: {...} }
    """
    ch = cert_hash
    if not ch.startswith("0x"):
        ch = "0x" + ch

    try:
        onchain_valid = is_certificate_valid(ch)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"on-chain check failed: {e}")

    # try to read DB (if you have get_certificate_by_hash in crud)
    from app.crud import get_certificate_by_hash
    db_rec = get_certificate_by_hash(ch)

    return {"cert_hash": ch, "onchain_valid": onchain_valid, "db_record": db_rec and dict(db_rec.__dict__) or None}

# GET /inspections — list inspections with pagination
from fastapi import Query

@app.get("/inspections")
def list_inspections(limit: int = Query(50, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """
    Returns a paginated list of inspection records from the DB.
    Query params:
      - limit: how many items to return (default 50)
      - offset: how many items to skip (default 0)
    """
    from app.crud import list_inspections as crud_list_inspections

    items = crud_list_inspections(limit=limit, offset=offset)
    # convert SQLModel objects to dicts if needed
    result = []
    for it in items:
        try:
            result.append(it.dict())   # SQLModel / Pydantic style
        except Exception:
            # fallback: convert object attributes to dict
            result.append({k: getattr(it, k) for k in dir(it) if not k.startswith("_") and not callable(getattr(it, k))})
    return {"count": len(result), "items": result, "limit": limit, "offset": offset}


from fastapi import Query, Header
from typing import Literal
# --------------------------
# 10) GET /inspection/{content_hash}
# --------------------------
@app.get("/inspection/{content_hash}")
def get_inspection(content_hash: str):
    """
    Return DB inspection record for the given content_hash (accepts with/without 0x).
    """
    from app.crud import get_inspection_by_content_hash
    ch = content_hash if content_hash.startswith("0x") else "0x" + content_hash
    rec = get_inspection_by_content_hash(ch)
    if not rec:
        raise HTTPException(status_code=404, detail="inspection not found")
    # SQLModel object -> dict
    try:
        return rec.dict()
    except Exception:
        return {k: getattr(rec, k) for k in dir(rec) if not k.startswith("_") and not callable(getattr(rec, k))}


# --------------------------
# 11) GET /certificates
# --------------------------
@app.get("/certificates")
def get_certificates(only_valid: bool = Query(False), limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """
    List certificates (optionally only valid ones).
    """
    from app.crud import list_certificates
    certs = list_certificates(only_valid=only_valid, limit=limit, offset=offset)
    out = []
    for c in certs:
        try:
            out.append(c.dict())
        except Exception:
            out.append({k: getattr(c, k) for k in dir(c) if not k.startswith("_") and not callable(getattr(c, k))})
    return {"count": len(out), "items": out, "limit": limit, "offset": offset}


# --------------------------
# 12) GET /certificate/{cert_hash}
# --------------------------
@app.get("/certificate/{cert_hash}")
def get_certificate(cert_hash: str):
    """
    Return DB certificate record for cert_hash.
    Accepts cert_hash with or without 0x.
    """
    from app.crud import get_certificate_by_hash
    ch = cert_hash if cert_hash.startswith("0x") else "0x" + cert_hash
    rec = get_certificate_by_hash(ch)
    if not rec:
        raise HTTPException(status_code=404, detail="certificate not found")
    try:
        return rec.dict()
    except Exception:
        return {k: getattr(rec, k) for k in dir(rec) if not k.startswith("_") and not callable(getattr(rec, k))}


# --------------------------
# 13) POST /admin/grant-role
# --------------------------
def _require_admin(api_key: str | None):
    if not api_key or api_key != getattr(settings, "ADMIN_API_KEY", None):
        raise HTTPException(status_code=401, detail="Missing or invalid admin API key")


# --------------------------
# 14) POST /admin/revoke-role
# --------------------------
@app.post("/admin/revoke-role")
def api_revoke_role(
    role: Literal["INSPECTOR_ROLE", "SUBMITTER_ROLE", "AGENT_ROLE", "ADMIN_ROLE"],
    target_address: str,
    x_admin_key: str | None = Header(None)
):
    _require_admin(x_admin_key)
    try:
        tx_receipt = revoke_role(settings.DEPLOYER_PK or settings.ADMIN_PK, role, target_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"revoke_role failed: {e}")
    return {"tx": tx_receipt.transactionHash.hex() if hasattr(tx_receipt, "transactionHash") else str(tx_receipt)}


# --------------------------
# 15) GET /roles/{address}
# --------------------------
@app.get("/roles/{address}")
def get_roles_for_address(address: str):
    try:
        inspector = has_role("INSPECTOR_ROLE", address)
        submitter = has_role("SUBMITTER_ROLE", address)
        agent = has_role("AGENT_ROLE", address)
        admin = has_role("ADMIN_ROLE", address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"error checking roles: {e}")
    return {
        "address": address,
        "roles": {
            "INSPECTOR_ROLE": inspector,
            "SUBMITTER_ROLE": submitter,
            "AGENT_ROLE": agent,
            "ADMIN_ROLE": admin
        }
    }


# --------------------------
# 16) GET /audit/verify-inspection
# --------------------------
@app.get("/audit/verify-inspection")
def audit_verify_inspection(content_hash: str):
    ch = content_hash if content_hash.startswith("0x") else "0x" + content_hash
    try:
        onchain = check_inspection_onchain(ch)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"on-chain check failed: {e}")
    db_rec = get_inspection_by_content_hash(ch)
    sig_ok = None
    if db_rec and getattr(db_rec, "signature", None):
        try:
            raw = build_inspection_raw_hash(
                settings.CONTRACT_ADDRESS,
                settings.CHAIN_ID,
                db_rec.content_hash,
                db_rec.summary_hash or "0x" + "00" * 32,
                db_rec.inspector,
                db_rec.inspector_timestamp,
                db_rec.nonce,
            )
            recovered = recover_signer_from_raw(raw, db_rec.signature)
            sig_ok = (recovered.lower() == db_rec.inspector.lower())
        except Exception:
            sig_ok = False
    return {"content_hash": ch, "onchain": onchain, "db_record": db_rec.dict() if db_rec else None, "signature_valid": sig_ok}


# --------------------------
# 17) GET /audit/verify-certificate
# --------------------------
@app.get("/audit/verify-certificate")
def audit_verify_certificate(cert_hash: str):
    ch = cert_hash if cert_hash.startswith("0x") else "0x" + cert_hash
    try:
        onchain_valid = is_certificate_valid(ch)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"on-chain check failed: {e}")
    from app.crud import get_certificate_by_hash
    db_rec = get_certificate_by_hash(ch)
    return {"cert_hash": ch, "onchain_valid": onchain_valid, "db_record": db_rec.dict() if db_rec else None}
