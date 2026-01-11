# Danic Blockchain Modules Overview

This document provides a brief explanation of the core system files
in the Danic blockchain repository. Each entry includes the purpose,
key features, and why it matters.

---

### gast_core.py

- **Purpose:** Implements the Global Account State Tree (GAST) core logic, handling deterministic CoinID computation, UTXO management, transactions, and GAST package application.  
- **Key Features:**  
  - Deterministic CoinID generation for UTXOs  
  - Live GlobalStateTree representing current blockchain state  
  - Single-owner transaction enforcement with signature verification  
  - Deterministic application of transaction packages (GAST)  
  - Node consensus logic to validate and commit GAST packages  
- **Why it matters:** Ensures all transactions and state updates are deterministic, auditable, and safely applied to the blockchain.  
- **Prototype Notes:** Experimental research code; single-owner rule enforced; uses BLS signatures (blspy).  

---

### handshake_reward.py

- **Purpose:** Manages witness quorum for reward finalization and generates deterministic master handshake for node synchronization.  
- **Key Features:**  
  - Collects witness votes for reward updates  
  - Ignores duplicate votes  
  - Commits reward balance atomically when quorum is reached  
  - Generates master handshake for state verification across nodes  
- **Why it matters:** Prevents unilateral reward updates and ensures verifiable, deterministic reward finality.  

---

### atomic_state.py

- **Purpose:** Performs atomic updates to blockchain state in LevelDB for Danic nodes.  
- **Key Features:**  
  - Applies spent and new UTXOs in one batch  
  - Updates H1 hash and sequence number per node  
  - Uses LevelDB write batches for atomicity  
- **Why it matters:** Guarantees all state changes are fully committed or not at all, preventing partial updates or state corruption.  

---

### syncing.py

- **Purpose:** (TBD) Handles network synchronization between nodes.  
- **Key Features:**  
  - (TBD)  
- **Why it matters:** Keeps all nodes in sync with the latest blockchain state.  

---

### bootstrap.py

- **Purpose:** (TBD) Manages network bootstrap and genesis coordination.  
- **Key Features:**  
  - (TBD)  
- **Why it matters:** Allows nodes to join the network securely and start from a known state.  

---

### Notes

- This index provides a **high-level overview**.  
- For implementation details, refer to each module’s source code.  
- As the project evolves, this document should be updated to reflect new modules and features.