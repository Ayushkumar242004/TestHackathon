# app/blockchain.py
import json, os
from web3 import Web3
from eth_account.messages import encode_defunct
from app.settings import settings
from hexbytes import HexBytes

# load ABI
# HERE = os.path.dirname(__file__)
# ABI_PATH = os.path.join(os.path.dirname(HERE), "artifacts", "Compliance.json")  # path at project root
# with open(ABI_PATH) as f:
#     artifact = json.load(f)
# ABI = artifact.get("abi", artifact)  # if the file is just the abi array

w3 = Web3(Web3.HTTPProvider(settings.RPC_URL))
# contract = w3.eth.contract(address=Web3.to_checksum_address(settings.CONTRACT_ADDRESS), abi=ABI)

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

# convenience contract calls
def record_inspection_with_signature(submitter_private_key, content_hash, summary_hash, inspector, inspector_timestamp, nonce, signature, meta=b""):
    acct = w3.eth.account.from_key(submitter_private_key)
    tx = contract.functions.recordInspectionWithSignature(
        content_hash, summary_hash or b'\x00'*32, inspector, inspector_timestamp, nonce, signature, meta
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 600000,
        "gasPrice": w3.eth.gas_price
    })
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

def issue_certificate(submitter_private_key, cert_hash, owner, expiry):
    acct = w3.eth.account.from_key(submitter_private_key)
    tx = contract.functions.issueCertificate(cert_hash, owner, expiry).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 400000,
        "gasPrice": w3.eth.gas_price
    })
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

def revoke_certificate(submitter_private_key, cert_hash):
    acct = w3.eth.account.from_key(submitter_private_key)
    tx = contract.functions.revokeCertificate(cert_hash).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000,
        "gasPrice": w3.eth.gas_price
    })
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt
