# app/blockchain.py
import json, os
from web3 import Web3
from eth_account.messages import encode_defunct
from app.settings import settings
from hexbytes import HexBytes

# load ABI
HERE = os.path.dirname(__file__)
ABI_PATH = os.path.join(os.path.dirname(HERE), "artifacts", "Compliance.json")  # path at project root
with open(ABI_PATH) as f:
    artifact = json.load(f)
ABI = artifact.get("abi", artifact)  # if the file is just the abi array

w3 = Web3(Web3.HTTPProvider(settings.RPC_URL))
contract = w3.eth.contract(address=Web3.to_checksum_address(settings.CONTRACT_ADDRESS), abi=ABI)

def get_chain_id():
    return int(settings.CHAIN_ID)

def _maybe_bytes32(value):
    """
    Accepts bytes, HexBytes, or hex string '0x...' and returns raw bytes (32 bytes).
    If given None or empty-like, returns 32 zero bytes.
    """
    if value is None:
        return b"\x00" * 32
    if isinstance(value, (bytes, bytearray, HexBytes)):
        # If it's bytes but not 32 long, left-pad with zeros to 32
        b = bytes(value)
        return b.rjust(32, b"\x00") if len(b) < 32 else b[:32]
    if isinstance(value, str):
        s = value
        if s.startswith("0x"):
            s = s[2:]
        # allow short hex (e.g., hashed text) — pad/truncate to 32 bytes
        b = bytes.fromhex(s)
        return b.rjust(32, b"\x00") if len(b) < 32 else b[:32]
    raise TypeError("Unsupported type for bytes32 conversion")

def build_inspection_raw_hash(contract_address, chain_id, content_hash, summary_hash, inspector, inspector_timestamp, nonce):
    """
    Build the Solidity-style keccak256 hash of:
      keccak256(address(contract), uint256(chainId), bytes32(contentHash),
                bytes32(summaryHash), address(inspector), uint256(inspectorTimestamp), bytes32(nonce))
    Returns raw bytes (32 bytes).
    """
    # prepare types and values
    types = ["address", "uint256", "bytes32", "bytes32", "address", "uint256", "bytes32"]

    addr = Web3.to_checksum_address(contract_address)
    inspector_addr = Web3.to_checksum_address(inspector)
    chain_id_int = int(chain_id)

    content_b = _maybe_bytes32(content_hash)
    summary_b = _maybe_bytes32(summary_hash)
    nonce_b = _maybe_bytes32(nonce)

    values = [
        addr,
        chain_id_int,
        content_b,
        summary_b,
        inspector_addr,
        int(inspector_timestamp),
        nonce_b
    ]

    # Note: web3.py function name is `solidity_keccak` (underscore)
    raw = Web3.solidity_keccak(types, values)  # returns bytes
    return raw

def recover_signer_from_raw(raw_hash: bytes, signature: str) -> str:
    """
    Recover the address that signed `raw_hash` using Ethereum personal_sign semantics
    (i.e. signMessage(arrayify(rawHash)) from ethers).
    """
    # raw_hash must be bytes
    if isinstance(raw_hash, str):
        # allow hexstring
        raw_hash = HexBytes(raw_hash)

    msg = encode_defunct(primitive=raw_hash)  # use eth-account to create signable message
    signer = w3.eth.account.recover_message(msg, signature=signature)
    return Web3.to_checksum_address(signer)

def _send_signed_transaction_and_wait(signed_tx):
    """
    Helper that works with both eth-account/web3 return shapes:
      - signed_tx.rawTransaction  (older)
      - signed_tx.raw_transaction (newer)
    Returns the transaction receipt.
    """
    raw = None
    # try both attribute names
    if hasattr(signed_tx, "rawTransaction"):
        raw = signed_tx.rawTransaction
    elif hasattr(signed_tx, "raw_transaction"):
        raw = signed_tx.raw_transaction
    else:
        # last-resort: look through dict representation
        try:
            raw = signed_tx.__dict__.get("rawTransaction") or signed_tx.__dict__.get("raw_transaction")
        except Exception:
            raw = None

    if raw is None:
        raise RuntimeError("Signed transaction object does not contain raw tx bytes (rawTransaction/raw_transaction)")

    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt


def record_inspection_with_signature(
    submitter_private_key,
    content_hash,
    summary_hash,
    inspector,
    inspector_timestamp,
    nonce,
    signature,
    meta=b"",
):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.recordInspectionWithSignature(
        HexBytes(content_hash),
        HexBytes(summary_hash or b"\x00"*32),
        Web3.to_checksum_address(inspector),
        int(inspector_timestamp),
        HexBytes(nonce),
        HexBytes(signature),
        meta,
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 800000,
        "gasPrice": w3.eth.gas_price,
    })

    # Sign the tx
    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    # Use helper to extract raw bytes and send
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def issue_certificate(submitter_private_key, cert_hash, owner, expiry):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.issueCertificate(
        HexBytes(cert_hash),
        Web3.to_checksum_address(owner),
        int(expiry),
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 400000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def revoke_certificate(submitter_private_key, cert_hash):
    acct = w3.eth.account.from_key(submitter_private_key)

    tx = contract.functions.revokeCertificate(HexBytes(cert_hash)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=submitter_private_key)
    receipt = _send_signed_transaction_and_wait(signed)
    return receipt


def _role_bytes32(role_name: str) -> bytes:
    # Accept either role name like "INSPECTOR_ROLE" or a bytes32 hex string
    if role_name.startswith("0x") and len(role_name) == 66:
        return HexBytes(role_name)
    return Web3.keccak(text=role_name)  # returns bytes

def grant_role(admin_private_key: str, role_name: str, target_address: str):
    acct = w3.eth.account.from_key(admin_private_key)
    role_b = _role_bytes32(role_name)
    tx = contract.functions.grantRole(role_b, Web3.to_checksum_address(target_address)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=admin_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def revoke_role(admin_private_key: str, role_name: str, target_address: str):
    acct = w3.eth.account.from_key(admin_private_key)
    role_b = _role_bytes32(role_name)
    tx = contract.functions.revokeRole(role_b, Web3.to_checksum_address(target_address)).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=admin_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def has_role(role_name: str, address: str) -> bool:
    role_b = _role_bytes32(role_name)
    return contract.functions.hasRole(role_b, Web3.to_checksum_address(address)).call()

def check_inspection_onchain(content_hash_hex: str) -> bool:
    # contract has mapping seenInspections(bytes32) -> bool
    h = content_hash_hex if content_hash_hex.startswith("0x") else "0x" + content_hash_hex
    return contract.functions.seenInspections(HexBytes(h)).call()

def is_certificate_valid(cert_hash_hex: str) -> bool:
    h = cert_hash_hex if cert_hash_hex.startswith("0x") else "0x" + cert_hash_hex
    return contract.functions.isCertificateValid(HexBytes(h)).call()