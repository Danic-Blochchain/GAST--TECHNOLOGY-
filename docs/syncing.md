# syncing.py

## Purpose
Handles full peer-to-peer synchronization for Danic blockchain nodes, ensuring each node stays consistent with the latest global state.

## Key Features
- Verifies handshake of connecting peers using Genesis hash and last known block
- Receives missing VBlock packages from peers
- Applies VBlocks atomically to the local node database using `apply_vblock_atomic`
- Ensures only verified peers are synced and rejects any unauthorized nodes

## Why it matters
Guarantees all nodes maintain a consistent, secure blockchain state, prevents forks, and locks synchronized blocks safely.

## Prototype Notes
- Uses JSON over TCP/ZMQ connections
- Can be extended for optimized peer selection and parallel syncing