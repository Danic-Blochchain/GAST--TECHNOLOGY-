# V3 — POST-QUANTUM SIGNING LAYER
**Danic Blockchain — Architecture Update**
*By Mr. Jammeh, Founder & CEO*
*12/04/2026*

---

## What This Update Adds

This document explains the V3 security upgrade to the Danic blockchain — the replacement of Ethereum's secp256k1 signing with **CRYSTALS-Dilithium3**, a post-quantum cryptographic standard finalized by NIST in 2024.

---

## Why This Was Necessary

The existing Danic architecture (V2) had a strong internal security model via the H1–H4 cryptographic state engine. However, the transaction signing layer was inherited from Ethereum — specifically **secp256k1 elliptic curve cryptography**.

This curve is vulnerable to **Shor's Algorithm** running on a sufficiently powerful quantum computer. If that attack becomes viable, an attacker could extract any wallet's private key directly from its public key — bypassing the entire H1–H4 layer entirely, since they could forge valid signatures.

**The H1–H4 chain was already quantum-resistant. The signing layer was not. V3 closes that gap.**

---

## What Changed

### Old Flow (V2)
```
User submits eth_sendRawTransaction (RLP encoded)
→ decode_raw_transaction() decodes it
→ Account.recover_transaction() identifies sender via secp256k1
→ process_gast_package() runs L1 / L2 / L3 checks
```

### New Flow (V3)
```
User submits signed GAST package (JSON + Dilithium3 signature)
→ validate_pq_signature() verifies sender via Dilithium3
→ process_gast_package() runs L1 / L2 / L3 checks (unchanged)
```

The L1, L2, and L3 validation logic is completely unchanged. The only replacement is at the signature verification entry point.

---

## The New Signing Layer (pq_signing.py)

### Key Generation
```python
public_key, private_key = generate_pq_keypair()
```
Replaces `Account.create()`. Uses Dilithium3 internally.

### Address Derivation
```python
address = get_danic_address(public_key)
# Returns: "DC" + SHA-256(public_key)[:40]
```
Replaces Ethereum address derivation from secp256k1.

### Signing a Transaction
```python
gast_package = build_signed_gast_package(
    private_key, public_key,
    sender_address, receiver_address,
    amount, previous_h1,
    input_utxo_keys, current_sequence,
    proposed_h3
)
```

### Validating on the Node
```python
pq_valid, pq_message = validate_pq_signature(gast_package)
if not pq_valid:
    return False, pq_message
```
This runs before L1, L2, L3 inside `process_gast_package()`.

---

## Error Codes

| Code | Meaning |
|---|---|
| PQ0 | Missing public key or signature field |
| PQ1 | Signature invalid — tampered or forged |
| PQ2 | Sender address does not match public key |
| PQ3 | Unexpected exception during validation |

---

## Full Security Layer — V3

| Layer | Method | Quantum Resistant |
|---|---|---|
| Transaction Signing | CRYSTALS-Dilithium3 | ✅ Yes |
| Address Derivation | SHA-256 of PQ public key | ✅ Yes |
| State Hashing H1–H4 | SHA-256 | ✅ Yes |
| Double-Spend Protection | H3 state lock + UTXO model | ✅ Yes |
| VBlock Integrity | SHA-256 H4 chain | ✅ Yes |

---

## Dependency

```bash
pip install dilithium-py
```

---

## Relationship to V2 Architecture

This update does not change the GAST packet structure, VBlock finality, P2P networking, or LevelDB storage model described in V2. It is a targeted replacement of the cryptographic entry point only.

For the full V2 architecture explanation see: `V2-ARCHITECTURE_EXPLAINED.md`

---

*Danic Blockchain — Built to survive the quantum era.*
