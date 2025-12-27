import json
from atomic_state import apply_vblock_atomic
from bootstrap import compute_handshake_hash

# ==============================================================================
# DANIC PEER SYNC MODULE
# ==============================================================================
# Handles full node peer synchronization:
# 1. Handshake verification
# 2. Receiving VBlock packages
# 3. Atomic state updates
# ==============================================================================

def recv_json(conn):
    """Receive JSON message from TCP/ZMQ connection"""
    raw = conn.recv(4096)
    return json.loads(raw.decode()) if raw else None

def send_json(conn, data):
    """Send JSON message over TCP/ZMQ connection"""
    conn.sendall(json.dumps(data).encode())

def handle_peer_sync(conn, db, local_chain):
    """
    Full peer sync process:
    - Verify handshake using Genesis + last known block
    - Receive missing VBlocks
    - Apply VBlocks atomically to local database
    """
    try:
        # Step 1: Receive handshake
        msg = recv_json(conn)
        if msg["type"] == "HANDSHAKE":
            expected = compute_handshake_hash(
                local_chain.genesis_h4,
                msg["last_block_number"],
                local_chain.get_block_h4(msg["last_block_number"])
            )

            if expected != msg["handshake_hash"]:
                print(f"🛑 Alien Node Detected ({msg.get('sender','unknown')}). Closing connection.")
                return

            # Handshake OK → Inform peer of tip
            send_json(conn, {"status": "HANDSHAKE_OK", "tip": local_chain.tip})

            # Step 2: Receive VBlocks
            while True:
                data = recv_json(conn)
                if not data or data["type"] == "END_SYNC":
                    break

                if data["type"] == "VBLOCK":
                    # Step 3: Apply atomically
                    apply_vblock_atomic(
                        db,
                        sender_id=data["sender"],
                        consumed_h4s=data["inputs"],
                        new_outputs=data["outputs"],
                        new_h1=data["h4"],
                        new_seq=data["seq"]
                    )
                    print(f"✅ Block {data['num']} synced and locked.")

    except Exception as e:
        print(f"Audit Failure for {msg.get('sender', 'unknown')}: {e}")