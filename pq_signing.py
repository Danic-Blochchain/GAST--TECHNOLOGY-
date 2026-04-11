# ==============================================================================
# pq_signing.py — DANIC POST-QUANTUM SIGNING LAYER
# Author: Mr. Jammeh — Danic Blockchain
#
# Replaces Ethereum secp256k1 signing with CRYSTALS-Dilithium3
# NIST Post-Quantum Cryptography Standard (FIPS 204 — 2024)
#
# Install: pip install dilithium-py
# ==============================================================================

import hashlib
import json
import time
from dilithium_py.dilithium import Dilithium3


# ==============================================================================
# KEY GENERATION
# Replaces: eth_account.Account.create()
# ==============================================================================

def generate_pq_keypair():
    """
    Generate a post-quantum Dilithium3 key pair.
    Returns: (public_key_bytes, private_key_bytes)
    """
    public_key, private_key = Dilithium3.keygen()
    return public_key, private_key


def get_danic_address(public_key: bytes) -> str:
    """
    Derive a DANIC wallet address from a post-quantum public key.
    Format: DC + first 40 chars of SHA-256(public_key)
    Replaces: Ethereum address derivation from secp256k1
    """
    pk_hash = hashlib.sha256(public_key).hexdigest()
    return "DC" + pk_hash[:40].upper()


# ==============================================================================
# SIGNING
# Replaces: Account.sign_transaction() + RLP encoding
# ==============================================================================

def sign_gast_package(private_key: bytes, gast_package: dict) -> str:
    """
    Sign a GAST package using Dilithium3.
    Returns: hex signature string
    """
    package_bytes = json.dumps(gast_package, sort_keys=True).encode('utf-8')
    signature = Dilithium3.sign(private_key, package_bytes)
    return signature.hex()


def verify_gast_signature(public_key: bytes, gast_package: dict, signature_hex: str) -> bool:
    """
    Verify a GAST package signature using Dilithium3.
    Replaces: Account.recover_transaction(raw_tx)
    Returns: True if valid, False if tampered or forged
    """
    try:
        package_bytes = json.dumps(gast_package, sort_keys=True).encode('utf-8')
        signature = bytes.fromhex(signature_hex)
        return Dilithium3.verify(public_key, package_bytes, signature)
    except Exception:
        return False


# ==============================================================================
# TRANSACTION BUILDER
# Replaces: eth_sendRawTransaction RLP flow
# ==============================================================================

def build_signed_gast_package(
    private_key: bytes,
    public_key: bytes,
    sender_address: str,
    receiver_address: str,
    amount: int,
    previous_h1: str,
    input_utxo_keys: list,
    current_sequence: int,
    proposed_h3: str
) -> dict:
    """
    Build and sign a complete GAST package using post-quantum keys.
    Drop-in replacement for the eth_sendRawTransaction flow in Gast-core.py
    """
    canonical_body = f"{sender_address}|{receiver_address}|{amount}|{time.time()}"
    tx_hash = hashlib.sha256(canonical_body.encode()).hexdigest()

    gast_package = {
        "sender_id":         sender_address,
        "receiver_id":       receiver_address,
        "amount":            amount,
        "tx_hash":           tx_hash,
        "previous_h1_hash":  previous_h1,
        "input_utxo_keys":   input_utxo_keys,
        "proposed_h3":       proposed_h3,
        "sequence":          current_sequence + 1,
        "timestamp":         int(time.time()),
        "sender_public_key": public_key.hex()
    }

    # Sign everything except the signature field itself
    gast_package["signature"] = sign_gast_package(private_key, {
        k: v for k, v in gast_package.items() if k != "signature"
    })

    return gast_package


# ==============================================================================
# VALIDATOR PRE-CHECK
# Add this at the TOP of process_gast_package() in Gast-core.py
# Before L1, L2, L3 checks
# ==============================================================================

def validate_pq_signature(gast_package: dict) -> tuple:
    """
    Validate the post-quantum signature on an incoming GAST package.

    Usage in Gast-core.py — process_gast_package():

        # --- PQ0: POST-QUANTUM SIGNATURE CHECK ---
        pq_valid, pq_message = validate_pq_signature(gast_package)
        if not pq_valid:
            return False, pq_message

        # --- L1: H1 VALIDATION (Lineage Check) ---
        ...continue existing checks...

    Returns: (True, "OK") or (False, "Error: reason")
    """
    try:
        sender_pk_hex = gast_package.get("sender_public_key")
        signature_hex = gast_package.get("signature")

        if not sender_pk_hex or not signature_hex:
            return False, "Error PQ0: Missing public key or signature."

        public_key = bytes.fromhex(sender_pk_hex)

        # Verify against package without the signature field
        package_to_verify = {
            k: v for k, v in gast_package.items() if k != "signature"
        }

        if not verify_gast_signature(public_key, package_to_verify, signature_hex):
            return False, "Error PQ1: Invalid post-quantum signature. Rejected."

        # Confirm sender address matches embedded public key
        derived_address = get_danic_address(public_key)
        if derived_address != gast_package.get("sender_id"):
            return False, "Error PQ2: Sender address does not match public key."

        return True, "OK"

    except Exception as e:
        return False, f"Error PQ3: Signature validation exception: {e}"


