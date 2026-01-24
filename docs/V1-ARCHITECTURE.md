Below is the technical breakdown of the architecture as it stands in the current codebase:

1. Core Stack & Custom Framework
Language & Identity: The core is written in Python, utilizing a fully custom architecture to maintain strict control over state-transition semantics.

State Engine: We use LevelDB (plyvel) for high-performance, key-value storage.

Atomic Commits: To ensure ledger integrity, all state changes are applied as atomic write batches via the apply_vblock_atomic function, preventing partial updates or state corruption.

2. The Triple-Hash State Lock (H1, H2, H3)
Our security model relies on a proprietary triple-hash commitment system to prevent double-spending without needing a global leader for every transaction:

H1 (Lineage): Tracks the sequential history of an account to ensure lineage.

H2 (Snapshot): A canonical serialization of an account's current UTXO set.

H3 (State Lock): A domain-separated commitment that anchors the Sender ID, Sequence, H1, and H2 to the specific transaction hash.

H4 (Integrity): An integrity hash calculated over the entire VBlock content to ensure secure chain linkage.

3. Networking & Dynamic Peer Discovery
The architecture uses a specialized multi-port strategy to isolate traffic and prevent head-of-line blocking:

Dynamic Bootstrapping: We move away from static IP dependencies by using a custom bootstrapper that manages active peer lists via ZMQ-based heartbeats and handshakes.

Port 9000/9001 (ZMQ): Used for high-speed GAST (transaction) gossip and asynchronous H1 state-update signals.

Port 7000 (Raw TCP): A dedicated synchronization layer for VBlock history using 4-byte length-prefix framing for deterministic data transfer.

4. Batch-Finality & Scaling
VBlock Triggers: Finality is achieved through VBlocks, triggered  every 20 seconds or when the buffer reaches 3,000 account updates (~1MB).

State-Bloat Mitigation: We utilize Overwrite Semantics. When a VBlock is committed, the system deletes all existing UTXOs for an account and replaces them with a new H2 snapshot, keeping the ledger size optimized relative to active accounts.

5. Developer Experience & Roadmap
EVM Compatibility: The prototype includes a Flask-based RPC layer supporting standard methods like eth_sendRawTransaction, eth_getBalance, and eth_getTransactionCount, allowing immediate integration with MetaMask and Web3.js.

2026 Goal: I have built this core to be "Mainnet-Ready" for a 2026 launch. My goal for our collaboration is to transition this validated Python logic into a performance-hardened production environment (such as Rust or Go) and formalize the validator committee BFT consensus.

# ARCHITECTURE

Danic Blockchain – Core Protocol & State Engine Specification

**Author & Protocol Architect:**  
Almamo Jammeh (Founder, Danic Blockchain)

**Status:** Mainnet-Targeted (2026)