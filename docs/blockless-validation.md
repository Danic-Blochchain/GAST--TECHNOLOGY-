# Blockless Validation – Danic Gas-Package Architecture

## Canonical Four-Layer Blueprint

### Objective
To define the complete architecture for deterministic transaction validation
using the four-layer hash model: **H1, H2, H3, H4**.

---

## Overview

Danic Blockchain is a **trustless, blockless transaction network**.

Instead of mining blocks or broadcasting coins like traditional blockchains,
every node maintains a **global UTXO-based account state (H2)**.

Transactions are submitted as **Gas Packages (GAST)** — deterministic proposals
for updating balances that are validated and committed without global blocks.

Consensus is achieved through **four cryptographic hash layers**, each with a
strict and non-overlapping responsibility.

---

## The Four Hash Layers

### H1 — Historical Transaction Hash (Lineage)
- Stores references (hashes) of all past gas packages per account
- Validates that a new gas package builds on the correct previous transaction
- Detects double-spending and lineage divergence

---

### H2 — Global Account State (UTXO Set)
- Stores all unspent balances as a map: **H4 Key → Value**
- Each account has its own H2 entry representing its current UTXO state
- Used to verify coin availability during validation

---

### H3 — State Integrity Hash (Verification Lock)
- Computed by both sender and validator **using the previous canonical state**
- Cryptographically locks a gas package to the exact H1 and H2 snapshot
- Prevents double-spending and state divergence

If H3 mismatches → the package is **rejected immediately**

---

### H4 — Deterministic UTXO Key (Persistence Address)
- Computed **only after H3 passes**
- Determines the exact hashed key where new UTXO values are stored in H2
- Provides deterministic yet unpredictable storage mapping

---

## Node State Requirements

Each node maintains:
- Latest **H1** per account
- Full **H2** global UTXO map (keyed by H4)
- Account **Sequence (Nonce)** for H3 calculation

---

## Gas Package Lifecycle

### Step 1: Gas Package Creation (Generator)

A user initiates a transfer of `X` coins.

The node constructs a **Gas Package (GAST)** containing:
- Transaction inputs (references to old H4 UTXO keys)
- Transaction outputs (receivers and amounts)
- Transaction fee
- `tx_hash`
- `previous_h1_hash`

The generator computes **H3** and broadcasts the package via TCP / ZMQ.

---

### Step 2: Gas Package Validation (Validator)

Validators perform a four-layer check:

**L1 — H1 Lineage Check**  
Ensures `previous_h1_hash` matches the latest account H1.

**L3 — H3 State Integrity Check**  
Recomputes expected H3 using local state.  
Mismatch → reject.

**L2 — H2 Viability Check**  
Verifies referenced UTXOs exist and are unspent.

**L4 — Atomic Commit**  
State update is applied atomically.

---

### Step 3: H4 & H2 Commit

- Old UTXOs are consumed
- New H4 keys are generated:
  - `H4_Change_Key`
  - `H4_Receiver_Key`
- H2 is updated with new balances
- Sequence is incremented
- New **H1** is stored

---

## Key Properties

- Trustless
- Blockless
- Deterministic
- Tamper-resistant

---

## Canonical Hash Formulas

### H1
### H1 — Historical Transaction Hash
Stores the historical reference for an accepted gas package.


---

### H2 — Global Account State
Maintains unspent balances keyed by deterministic H4 addresses.


---

### H3 — State Integrity Hash (Verification Lock)
Cryptographically binds a gas package to the previous canonical network state.


---

### H4 — Deterministic UTXO Key (Persistence Address)
Determines the exact storage location for newly created UTXOs.


**Output Index Options**
- `CHG` — Sender change
- `RECV` — Receiver output


