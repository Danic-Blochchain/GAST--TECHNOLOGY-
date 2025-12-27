import plyvel

def apply_vblock_atomic(db, sender_id, consumed_h4s, new_outputs, new_h1, new_seq):
    addr_prefix = sender_id.lower().encode()
    with db.write_batch(transaction=True) as wb:
        # Spend old UTXOs
        for h4 in consumed_h4s:
            wb.delete(b"utxo:" + addr_prefix + b":" + h4.encode())
        # Add new UTXOs
        for h4_key, value in new_outputs.items():
            wb.put(b"utxo:" + addr_prefix + b":" + h4_key.encode(), str(value).encode())
        # Update H1 and sequence
        wb.put(b"h1:" + addr_prefix, new_h1.encode())
        wb.put(b"seq:" + addr_prefix, str(new_seq).encode())
    return True