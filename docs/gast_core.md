### gast_core.py

- **Purpose:** Implements the Global Account State Tree (GAST) core logic for Danic Blockchain, handling deterministic CoinID computation, UTXO management, transactions, and GAST package application.  
- **Key Features:**  
  - Deterministic CoinID generation for UTXOs.  
  - Live GlobalStateTree representing the current blockchain state.  
  - Single-owner transaction enforcement with signature verification.  
  - Deterministic application of transaction packages (GAST) with state root computation.  
  - Node consensus logic to validate and commit GAST packages.  
- **Why it matters:** Ensures all transactions and state updates are deterministic, auditable, and safely applied to the blockchain.  
- **Prototype Notes:**  
  - Experimental research code (not production-ready).  
  - Single-owner input rule enforced.  
  - Uses BLS signatures (blspy) for validation.