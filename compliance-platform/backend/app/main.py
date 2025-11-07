# backend/app/main.py
import os
import time
import tempfile
from typing import Optional

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


@app.post("/issue-certificate")
def issue_certificate_endpoint(data: IssueCertificateIn):
    """
    Issue a certificate on chain, store certificate metadata in DB and return tx + cert_hash.
    """
    cert_hash = w3.keccak(text=data.cert_id).hex()
    try:
        receipt = issue_certificate(settings.SUBMITTER_PK, cert_hash, data.owner, data.expiry or 0)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    obj = {
        "cert_hash": cert_hash,
        "issuer": w3.eth.account.from_key(settings.SUBMITTER_PK).address,
        "owner": data.owner,
        "expiry": data.expiry,
        "revoked": False,
        "issued_at": int(time.time()),
        "tx_hash": receipt.transactionHash.hex() if hasattr(receipt, "transactionHash") else str(receipt),
    }
    create_certificate(obj)
    return {"tx": receipt.transactionHash.hex() if hasattr(receipt, "transactionHash") else str(receipt), "cert_hash": cert_hash}


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
