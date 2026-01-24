# Danic Blockchain Architecture — Explained (v2)

> This document is a high-level explanatory summary of the canonical
> `ARCHITECTURE.md`. It is intended to help readers understand the
> design philosophy and system flow of the Danic Blockchain.
>
> In case of any discrepancy, the technical specification in
> `ARCHITECTURE.md` is authoritative.

---

## Purpose of This Document

This document provides a simplified but accurate explanation of the
Danic Blockchain architecture, moving from the cryptographic state
engine to the peer-to-peer networking layer.

It is written to help developers, validators, partners, and non-core
contributors understand **how Danic moves beyond traditional
block-based transaction models** into a **state-driven, GAST-based
execution system**.

---

## A. Cryptographic State Engine (H1 – H4)

Unlike traditional blockchains that rely on global leader-election
for every block, Danic uses a multi-layer cryptographic locking model
to guarantee account integrity and prevent double-spending.

### H1 — Lineage Hash
A recursive hash that represents the full historical lineage of an
account. Every valid state transition must cryptographically link to
the previous H1, ensuring ordered and tamper-proof account history.

### H2 — State Snapshot
A canonical serialization of an account’s current UTXO (Unspent
Transaction Output) set. H2 represents the complete spendable state
of an account at a specific moment in time.

### H3 — Integrity State Lock
A domain-separated cryptographic commitment that binds together:

- Sender ID
- Sequence Number
- H1 (Lineage Hash)
- H2 (State Snapshot)
- Transaction Hash

H3 acts as the **primary double-spend protection mechanism**, ensuring
that a transaction is only valid if the sender’s state has not changed
since the transaction was signed.

### H4 — Integrity & Linkage Hash
H4 is used for:
- Deterministic UTXO key generation
- Integrity hashing of entire VBlocks

This guarantees both local data consistency and secure linkage between
state batches.

---

## B. State Transition Logic (The GAST Package)

In Danic, a transaction is referred to as a **GAST Package**. Each
package represents a complete and self-contained state transition.

Validation is performed in three layers:

### L1 — Lineage Check
Verifies that the transaction’s `previous_h1` matches the latest H1
stored in the local database for the sender.

### L2 — Viability Check
Confirms that:
- Referenced UTXO keys exist
- Total input value covers the transaction amount plus the fixed
  platform fee (0.01)

### L3 — Integrity Lock Verification
Recomputes the expected H3 to ensure the sender’s account state has not
changed since the transaction was signed.

Only transactions that pass all three layers are accepted for batching.

---

## C. Batch Finality via VBlocks

To maximize throughput and minimize coordination overhead, Danic does
not finalize transactions individually.

Instead, validated state transitions are committed in **VBlocks**.

### VBlock Triggers
A VBlock is created when either:
- 20 seconds have elapsed, or
- 3,000 account updates (~1MB) have been buffered

### Atomic State Commit
All state changes within a VBlock are applied using atomic LevelDB
write batches. This guarantees that either **all updates succeed** or
**none are applied**, preventing partial state corruption.

### Overwrite Principle
To prevent state bloat, Danic deletes all previous UTXOs for an account
during VBlock commit and replaces them with the new H2 snapshot.

This keeps the ledger size proportional to active accounts rather than
historical transaction volume.

---

## D. Specialized Multi-Port Networking

Danic uses a custom peer-to-peer networking stack that separates
high-frequency gossip from heavy synchronization traffic.

### Port 9000 / 9001 — ZMQ PUSH/PULL
- High-speed transaction gossip (GAST packages)
- Asynchronous H1 state-update signals

### Port 6000 — ZMQ REQ/REP
- Account state queries (H1, Sequence, UTXOs)

### Port 7000 — Raw TCP
- Deterministic VBlock history synchronization
- Uses 4-byte length-prefixed framing

This separation prevents head-of-line blocking and improves overall
network efficiency.

---

## E. Dynamic Peer Discovery (Bootstrapper)

Danic eliminates static IP dependencies through a custom bootstrapper
service.

Nodes identify active peers using heartbeats and handshake messages,
allowing the network to adapt dynamically as nodes join or leave.

---

## F. Developer Experience & EVM Compatibility

### JSON-RPC Interface
A Flask-based JSON-RPC layer supports standard Ethereum methods such as:
- `eth_sendRawTransaction`
- `eth_getBalance`
- `eth_getTransactionCount`

This enables immediate compatibility with MetaMask, Web3.js, and
existing Ethereum tooling.

### Hybrid Storage Model
Danic combines the performance of a key-value store (LevelDB) with the
structural guarantees of a blockchain ledger.

---

## Architectural Summary

This architecture demonstrates how Danic transitions from traditional
block-based transaction ordering to a **GAST-based state model**.

Each node maintains an up-to-date account state and applies validated
state transitions instantly, without requiring complex global
consensus for every transaction.

Batch finality via VBlocks ensures security, scalability, and strong
state integrity.

---

**Author:**  
Almamo Jammeh  
Founder & CEO, Danic Blockchain

**Document Version:** v2 (Explanatory)  
**Date:** 2026-01-23
