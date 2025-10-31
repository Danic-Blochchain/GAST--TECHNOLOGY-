"""
gast_core.py

GAST (Global Account State Tree) core logic for Danic Blockchain.

Simplified, public-safe prototype implementing:
- Deterministic CoinID computation
- GlobalStateTree (live UTXO set)
- Transactions (single-owner input rule)
- GAST aggregate package application
- Deterministic validation and GST root computation

IMPORTANT:
- This is experimental research code (not production ready).
- Transactions must have all inputs owned by the same public key (single-owner).
- Signature scheme: BLS (blspy) - verify a single signature from the owner.
"""

import hashlib
import copy
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional

# blspy is required for real signature operations. If not installed,
# you can still read algorithm, but runtime verification will fail.
try:
    from blspy import G1Element, G2Element, AugSchemeMPL
except Exception:
    # Provide minimal placeholders to keep static analysis possible.
    # Do NOT use placeholders in production.
    G1Element = bytes
    G2Element = bytes
    class AugSchemeMPL:
        @staticmethod
        def verify(pubkey, message, signature):
            # placeholder: always False if blspy not present
            return False

# ------------- Configuration Constants ----------------
CHAIN_ID = b"CHAIN1"                 # replace with real chain id for production
GENESIS_HASH = hashlib.sha256(b"GENESIS").digest()
COINID_OUTPUT_INDEX_BYTES = 4
AMOUNT_BYTES = 8
G1_BYTES = 48                         # typical compressed G1 size (documented)
# ------------------------------------------------------

logger = logging.getLogger("gast_core")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def sha256(data: bytes) -> bytes:
    """Return sha256 digest of input bytes."""
    return hashlib.sha256(data).digest()


@dataclass(frozen=True)
class CoinData:
    owner_pubkey: G1Element
    amount: int
    source_tx_hash: bytes  # 32-byte tx hash reference

    def serialize(self) -> bytes:
        """Serialize coin metadata deterministically."""
        # For G1Element use its compressed bytes representation.
        pk_bytes = bytes(self.owner_pubkey) if not isinstance(self.owner_pubkey, bytes) else self.owner_pubkey
        return pk_bytes + int(self.amount).to_bytes(AMOUNT_BYTES, "big") + self.source_tx_hash

    @staticmethod
    def deserialize(b: bytes) -> "CoinData":
        """Deserialize bytes into CoinData — expects fixed layout.

        Note: This method assumes compressed G1Element size = G1_BYTES.
        """
        if len(b) < G1_BYTES + AMOUNT_BYTES + 32:
            raise ValueError("CoinData bytes length is too short")
        pk = G1Element.from_bytes(b[:G1_BYTES]) if hasattr(G1Element, "from_bytes") else b[:G1_BYTES]
        amt = int.from_bytes(b[G1_BYTES:G1_BYTES + AMOUNT_BYTES], "big")
        src = b[G1_BYTES + AMOUNT_BYTES:G1_BYTES + AMOUNT_BYTES + 32]
        return CoinData(pk, amt, src)


class GlobalStateTree:
    """Live UTXO set keyed by CoinID (bytes)."""
    def __init__(self):
        self.tree: Dict[bytes, CoinData] = {}

    def get(self, coin_id: bytes) -> Optional[CoinData]:
        return self.tree.get(coin_id)

    def update(self, coin_id: bytes, coin_data: CoinData):
        self.tree[coin_id] = coin_data

    def spend(self, coin_id: bytes):
        if coin_id in self.tree:
            del self.tree[coin_id]

    def all_items(self):
        return sorted(self.tree.items())


def compute_coin_id(chain_id: bytes, genesis_hash: bytes, origin_tx_hash: bytes,
                    output_index: int, recipient_pubkey: G1Element, output_amount: int) -> bytes:
    """Compute deterministic CoinID for a UTXO."""
    pk_bytes = bytes(recipient_pubkey) if not isinstance(recipient_pubkey, bytes) else recipient_pubkey
    data = bytearray()
    data.extend(chain_id)
    data.extend(genesis_hash)
    data.extend(origin_tx_hash)
    data.extend(int(output_index).to_bytes(COINID_OUTPUT_INDEX_BYTES, "big"))
    data.extend(pk_bytes)
    data.extend(int(output_amount).to_bytes(AMOUNT_BYTES, "big"))
    return sha256(bytes(data))


@dataclass
class Transaction:
    """Simple transaction model.

    Note: All input CoinData must have the SAME owner_pubkey in this prototype.
    """
    source_coin_ids: List[bytes]
    recipient_pubkeys: List[G1Element]
    amounts: List[int]
    signature: G2Element  # signature by owner over tx.hash()

    def hash(self) -> bytes:
        data = b"".join(self.source_coin_ids)
        data += b"".join(bytes(pk) if not isinstance(pk, bytes) else pk for pk in self.recipient_pubkeys)
        data += b"".join(int(a).to_bytes(AMOUNT_BYTES, "big") for a in self.amounts)
        return sha256(data)


def apply_transaction(tx: Transaction, gst: GlobalStateTree, chain_id: bytes, genesis_hash: bytes) -> bool:
    """Apply a single transaction to the provided GST.

    Returns True if applied successfully, False otherwise.
    This prototype enforces a single-owner rule for inputs: all inputs must be owned by same public key.
    """
    # Basic shape checks
    if len(tx.recipient_pubkeys) != len(tx.amounts):
        logger.error("Transaction malformed: recipients and amounts length mismatch")
        return False
    if any(a < 0 for a in tx.amounts):
        logger.error("Transaction malformed: negative amount")
        return False
    if len(tx.source_coin_ids) == 0:
        logger.error("Transaction malformed: no inputs")
        return False

    # Gather inputs & ensure they exist
    total_in = 0
    owner_pk = None
    for cid in tx.source_coin_ids:
        coin = gst.get(cid)
        if not coin:
            logger.error("Missing input UTXO: %s", cid.hex())
            return False
        if owner_pk is None:
            owner_pk = coin.owner_pubkey
        else:
            # enforce single-owner inputs in this prototype
            if coin.owner_pubkey != owner_pk:
                logger.error("Multiple owners detected in inputs — not allowed in prototype")
                return False
        total_in += coin.amount

    # Verify signature once against owner_pk
    if owner_pk is None:
        logger.error("No owner found for inputs")
        return False

    if not AugSchemeMPL.verify(owner_pk, tx.hash(), tx.signature):
        logger.error("Signature verification failed")
        return False

    total_out = sum(tx.amounts)
    if total_out > total_in:
        logger.error("Overspend attempt: total_out=%d total_in=%d", total_out, total_in)
        return False

    # Apply spend
    for cid in tx.source_coin_ids:
        gst.spend(cid)

    # Create outputs
    tx_hash = tx.hash()
    for idx, (recipient, amt) in enumerate(zip(tx.recipient_pubkeys, tx.amounts)):
        new_cid = compute_coin_id(chain_id, genesis_hash, tx_hash, idx, recipient, amt)
        gst.update(new_cid, CoinData(recipient, amt, tx_hash))

    # (Optional) create change output if needed (not implemented automatically)
    return True


@dataclass
class GAST:
    """Global Aggregated State Transaction (a package of transactions)."""
    tx_list: List[Transaction]
    prev_state_root: bytes
    new_state_root: Optional[bytes]
    height: int
    proposer_pubkey: G1Element

    def compute_hash(self) -> bytes:
        data = b"".join(tx.hash() for tx in self.tx_list)
        data += self.prev_state_root
        data += (self.new_state_root if self.new_state_root is not None else b'\x00' * 32)
        data += int(self.height).to_bytes(8, "big")
        return sha256(data)


class NodeConsensus:
    """Node consensus logic to validate and commit GAST packages."""
    def __init__(self, gst: GlobalStateTree, node_pubkey: G1Element):
        self.gst = gst
        self.node_pubkey = node_pubkey
        self.last_gast_hash: Optional[bytes] = None
        self.gast_pool: Dict[bytes, GAST] = {}

    def receive_gast(self, gast: GAST) -> bool:
        gh = gast.compute_hash()
        if gh in self.gast_pool:
            logger.debug("GAST already seen")
            return False
        self.gast_pool[gh] = gast
        return self.validate_and_commit(gast)

    def validate_and_commit(self, gast: GAST) -> bool:
        # 1. Verify previous state root matches local GST
        if self.compute_gst_root() != gast.prev_state_root:
            logger.warning("Reject: prev state root mismatch")
            return False

        # 2. Apply transactions deterministically on a copy
        temp_gst = copy.deepcopy(self.gst)
        for tx in gast.tx_list:
            ok = apply_transaction(tx, temp_gst, CHAIN_ID, GENESIS_HASH)
            if not ok:
                logger.warning("Reject: invalid transaction during GAST validation")
                return False

        # 3. Compute new root and compare
        new_root = self.compute_gst_root(temp_gst)
        if gast.new_state_root and new_root != gast.new_state_root:
            logger.warning("Reject: new state root mismatch")
            return False

        # 4. Commit GST update
        self.gst = temp_gst
        self.last_gast_hash = gast.compute_hash()
        logger.info("GAST committed, GST updated at height %d", gast.height)
        return True

    def compute_gst_root(self, gst: Optional[GlobalStateTree] = None) -> bytes:
        """Compute a deterministic root over the GST.

        NOTE: This is a simple concatenation-based root for prototype use only.
        For production, replace this with a Merkle or Sparse Merkle root for efficiency.
        """
        gst = gst or self.gst
        combined = b"".join(cid + coin.serialize() for cid, coin in gst.all_items())
        return sha256(combined)


# Optional test helpers (do not run on production network)
if __name__ == "__main__":
    logger.info("GAST core module loaded as script. This is a prototype module.")
    logger.info("Please run tests and use blspy keys to perform signature checks.")
