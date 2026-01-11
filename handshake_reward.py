"""
DANIC V2.0 – Reward Quorum & Master Handshake
"""

import hashlib
import logging
import collections

# --- Quorum Configuration ---
WITNESS_THRESHOLD = 3  # Minimum matching RGPs required to commit
GENESIS_HASH = "000000000001D4N1CG4ST"

logger = logging.getLogger("DANIC_QUORUM")


class RewardQuorumManager:
    """
    Collects reward state reports from witnesses and commits
    the reward state only after quorum is reached.
    """

    def __init__(self, db_ref):
        self.db = db_ref

        # { rgp_hash: [witness_ids] }
        self.pending_rgps = collections.defaultdict(list)

        # { rgp_hash: rgp_message }
        self.rgp_data_store = {}

    def get_rgp_hash(self, node_id, balance, height):
        """
        Creates a deterministic fingerprint for a reward state update.
        """
        payload = f"{node_id}{balance}{height}{GENESIS_HASH}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def process_incoming_rgp(self, rgp_msg):
        """
        Triggered when a reward sync message is received.
        Logic: Collect → Count → Commit
        """
        target_id = rgp_msg["node_id"]
        claimed_bal = rgp_msg["reward_balance"]
        at_height = rgp_msg["network_height"]
        witness_id = rgp_msg["witness_id"]

        fingerprint = self.get_rgp_hash(target_id, claimed_bal, at_height)

        # Ignore duplicate witness votes
        if witness_id in self.pending_rgps[fingerprint]:
            return

        self.pending_rgps[fingerprint].append(witness_id)
        self.rgp_data_store[fingerprint] = rgp_msg

        vote_count = len(self.pending_rgps[fingerprint])
        logger.info(
            f"QUORUM_PROGRESS | Node {target_id} | "
            f"Votes: {vote_count}/{WITNESS_THRESHOLD}"
        )

        if vote_count >= WITNESS_THRESHOLD:
            self.finalize_reward_state(fingerprint)

    def finalize_reward_state(self, fingerprint):
        """
        Commits the finalized reward state to the database atomically.
        """
        data = self.rgp_data_store[fingerprint]

        target_id = data["node_id"]
        final_bal = data["reward_balance"]
        height = data["network_height"]

        try:
            batch = self.db.write_batch()
            batch.put(
                f"reward_pocket:{target_id}".encode(),
                str(final_bal).encode()
            )
            batch.put(
                f"last_audit_height:{target_id}".encode(),
                str(height).encode()
            )
            batch.write()

            logger.info(
                f"CONCRETE_FINALITY | ID {target_id} balanced at "
                f"{final_bal} (Quorum Met)"
            )

            del self.pending_rgps[fingerprint]
            del self.rgp_data_store[fingerprint]

        except Exception as e:
            logger.error(f"DB_COMMIT_ERROR: {e}")


# --- Unified Handshake (Request Side) ---

def create_master_handshake(node_id, height, h4, balance):
    """
    Generates a deterministic master handshake hash
    using Genesis + verified block hash + reward balance.
    """
    formula = f"{GENESIS_HASH}{h4}{balance}"
    master_hash = hashlib.sha256(formula.encode()).hexdigest()

    return {
        "type": "MASTER_HANDSHAKE",
        "node_id": node_id,
        "last_block_number": height,
        "vblock_h4": h4,
        "reward_balance": balance,
        "master_hash": master_hash,
    }
