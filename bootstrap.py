import hashlib

# ==============================================================================
# DANIC BOOTSTRAP / HANDSHAKE MODULE
# ==============================================================================
# This module handles the node bootstrapping verification.
# When a new node joins the network, it verifies the chain by computing
# a handshake hash using the Genesis hash + block number + block hash.
# ==============================================================================

# Handshake domain constant
HANDSHAKE_DOMAIN = b"DANIC-HANDSHAKE-V1"

def compute_handshake_hash(genesis_h4, block_num, block_h4):
    """
    Compute the handshake hash for bootstrapping and verification.
    
    Parameters:
    - genesis_h4 (str): Hex string of the genesis block hash
    - block_num (int): Block number