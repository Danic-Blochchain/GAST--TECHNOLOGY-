# Handshake & Reward Quorum (V2.0)

This document explains the reward quorum and master handshake
logic implemented in `handshake_reward.py`.

## Overview

The module has two main responsibilities:

1. Finalize reward balances using witness quorum.
2. Generate a deterministic master handshake for node state synchronization.

No single node can update reward state alone.

## Reward Quorum Logic

Reward updates are received from multiple witness nodes (RGPs).  
Each update is fingerprinted using:

- node_id  
- reward_balance  
- network_height  
- genesis hash

Votes are collected in memory.  
When the number of matching votes reaches the threshold, the reward is committed atomically to the database.  
Duplicate votes are ignored.

## Master Handshake

The master handshake allows nodes to verify each other's state.  
The handshake hash is generated from:

- Genesis hash  
- Verified block hash (H4)  
- Reward balance

This ensures nodes agree on core state before syncing.

## Security Properties

- Prevents unilateral reward updates  
- Ignores duplicate witness votes  
- Ensures deterministic reward finality  
- Provides verifiable handshake identity