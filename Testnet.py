import hashlib
import plyvel
import requests
import json
import rlp
import time
import threading
import logging
import zmq
import socket
import sys
import random
import os
from flask import Flask, request, jsonify
from eth_account import Account
from web3 import Web3
from eth_account._utils.legacy_transactions import Transaction
from waitress import serve
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
import danic_balance

# --- Core Configuration Parameters ---
BOOTSTRAP_IPS = [
    "127.0.0.1",  # Replace with the actual public IP address of your master boot node
]
P2P_PORT = 8000
REST_PORT = 8041  

VOTE_PORT, SYNC_PORT, BLOCK_DOWNLOAD_PORT = 6000, 9000, 7000
VOTE_TIMEOUT, IP_FETCH_INTERVAL = 15, 900
SYNC_THRESHOLD = 1000
GOSSIP_INTERVAL = 60
HEARTBEAT_TIMEOUT = 10

# Network Genesis Token Shield Check
DANIC_GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

VAULT_DIR = "vault"
VAULT_FILE = os.path.join(VAULT_DIR, "peer_matrix.dat")

logger = logging.getLogger("DANIC_VALIDATOR")
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')

app = Flask(__name__)
db = plyvel.DB('danic_db', create_if_missing=True)
GENESIS_WALLET = Web3.to_checksum_address(danic_balance.GENESIS_WALLET)
CHAIN_ID = "0x1e61"
GENESIS_PREV_HASH = hashlib.sha256(CHAIN_ID.encode()).hexdigest()

blockchain_data = {"chainId": CHAIN_ID, "blockNumber": "0x0", "lastBlockHash": "0x" + GENESIS_PREV_HASH}
mempool, mempool_lock = {}, threading.Lock()
confirmed_mempool, confirmed_mempool_lock = [], threading.Lock()

ASYNC_EXECUTOR = ThreadPoolExecutor(max_workers=5)

# --- Dynamic Gas Limits and Platform Fees ---
FEE_RATE = 0.0075      
MAX_FEE = int(2000 * 10**18)  
BASE_GAS_LIMIT = 21000 
MIN_GAS_PRICE = 1 
BASE_UNIT_CONVERSION = 10**18 

def calculate_platform_fee(value_wei):
    platform_fee = int(value_wei * FEE_RATE)
    return min(platform_fee, MAX_FEE)

def dynamic_gas_limit(value_wei):
    value_eth = value_wei // BASE_UNIT_CONVERSION
    gas_limit = BASE_GAS_LIMIT + (value_eth * 1000)
    return gas_limit

def dynamic_gas_price(value_wei):
    platform_fee = calculate_platform_fee(value_wei)
    gas_limit = dynamic_gas_limit(value_wei)
    if gas_limit == 0:
        return 1
    return max(platform_fee // gas_limit, 1)

# --- Disk Vault Local File Caching ---
def save_peer_matrix_to_vault(peer_list):
    try:
        if not os.path.exists(VAULT_DIR):
            os.makedirs(VAULT_DIR)
        payload_data = {"timestamp": int(time.time()), "peers": peer_list}
        serialized_json = json.dumps(payload_data, sort_keys=True)
        integrity_signature = hashlib.sha256(serialized_json.encode('utf-8')).hexdigest()
        vault_record = {"signature": integrity_signature, "payload": payload_data}
        with open(VAULT_FILE, "w") as f:
            json.dump(vault_record, f, indent=4)
        logger.info(f"[Vault Storage Engine] Securely serialized peer list data structure matrix to {VAULT_FILE}")
    except Exception as e:
        logger.error(f"[Vault Error] Failed archiving network directory to file system paths: {e}")

class PeerPersistence:
    def __init__(self, filename='last_active_peers.json'):
        self.filename = filename
        self.lock = threading.Lock()

    def save_peers(self, peers):
        with self.lock:
            try:
                with open(self.filename, 'w') as f:
                    json.dump(list(peers), f)
            except Exception as e:
                logger.error(f"[Persistence Error] {e}")

    def load_peers(self):
        with self.lock:
            try:
                with open(self.filename, 'r') as f:
                    return set(json.load(f))
            except:
                return set()

class PeerManager:
    def __init__(self, my_ip, bootstrap_ips, persistence_manager):
        self.my_ip = my_ip
        self.persistence_manager = persistence_manager
        self.peers = set()
        self.bootstrap_ips = set(bootstrap_ips)
        self.peer_scores = {}
        self.lock = threading.Lock()
        self.PEER_SCORE_CAP = 20

        self.gossip_thread = threading.Thread(target=self._gossip_loop, daemon=True)
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)

    def start(self):
        self.server_thread.start()
        self.gossip_thread.start()
        self.heartbeat_thread.start()
        logger.info("[Network Daemon] Initialized multi-layered connection listeners.")
        self.run_discovery_sequence()

    def run_discovery_sequence(self):
        logger.info("[P2P Handshake Sequence] Contacting authentication reflector arrays...")
        discovered_ip = None
        shuffled_bootstraps = list(self.bootstrap_ips)
        random.shuffle(shuffled_bootstraps)

        # Step 1: Discover Identity IP
        for target_b_ip in shuffled_bootstraps:
            try:
                discover_url = f"http://{target_b_ip}:{REST_PORT}/discover"
                response = requests.get(discover_url, timeout=5)
                if response.status_code == 200:
                    discovered_ip = response.json().get("your_ip")
                    logger.info(f"[Handshake Step 1] Discovered public networking interface endpoint identity: {discovered_ip}")
                    self.my_ip = discovered_ip
                    break
            except Exception:
                logger.warning(f"[Handshake Warning] Reflector communication error on target seed node: {target_b_ip}")

        if not discovered_ip:
            logger.warning("[Handshake Warning] Falling back to default address maps.")
            self.my_ip = "127.0.0.1"

        # Step 2: Present Token Signature Payload
        for target_b_ip in shuffled_bootstraps:
            try:
                handshake_url = f"http://{target_b_ip}:{REST_PORT}/peer-handshake"
                payload = {
                    "genesis_hash": DANIC_GENESIS_HASH,
                    "peer_ip": self.my_ip,
                    "p2p_port": P2P_PORT
                }
                logger.info(f"[Handshake Step 2] Sending verification token payload to: {target_b_ip}")
                reg_response = requests.post(handshake_url, json=payload, timeout=5)
                
                if reg_response.status_code == 200:
                    active_peers = reg_response.json().get("active_peers", [])
                    logger.info(f"[Access Authorization Cleared] Node verified. Fetched network listings: {active_peers}")
                    save_peer_matrix_to_vault(active_peers)
                    
                    with self.lock:
                        for endpoint in active_peers:
                            peer_ip = endpoint.split(":")[0]
                            if peer_ip != self.my_ip:
                                self.peers.add(peer_ip)
                                self.peer_scores[peer_ip] = 10
                    break
            except Exception as e:
                logger.error(f"[Access Rejected] Target seed engine registration processing failed: {e}")

        if not self.peers:
            self.attempt_connection_in_parallel(self.bootstrap_ips)
            loaded_peers = self.persistence_manager.load_peers()
            self.attempt_connection_in_parallel(loaded_peers)

    def attempt_connection_in_parallel(self, ips_to_try):
        successful_connection = False
        with ThreadPoolExecutor(max_workers=min(len(ips_to_try), 10)) as executor:
            future_to_ip = {
                executor.submit(self._send_request, ip, {"type": "peer_request"}, timeout=5): ip
                for ip in ips_to_try if ip != self.my_ip
            }
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    future.result()
                    with self.lock:
                        if ip not in self.peers:
                            self.peers.add(ip)
                            self.peer_scores[ip] = 10
                    successful_connection = True
                except Exception:
                    with self.lock:
                        self.peers.discard(ip)
                        self.peer_scores.pop(ip, None)
        return successful_connection

    def _gossip_loop(self):
        while True:
            time.sleep(GOSSIP_INTERVAL)
            with self.lock:
                active_peers = [p for p in self.peers if self.peer_scores.get(p, 0) > 0]
                if active_peers:
                    peers_to_gossip = random.choices(
                        active_peers,
                        k=min(len(active_peers), 5),
                        weights=[self.peer_scores.get(p, 1) for p in active_peers],
                    )
                else:
                    peers_to_gossip = []

            for ip in peers_to_gossip:
                try:
                    self._send_request(ip, {"type": "gossip_request"})
                except Exception:
                    pass
            self.persistence_manager.save_peers(self.peers)

    def _heartbeat_loop(self):
        while True:
            time.sleep(HEARTBEAT_TIMEOUT)
            with self.lock:
                peers_to_check = list(self.peers)

            for ip in peers_to_check:
                try:
                    self._send_request(ip, {"type": "heartbeat"}, timeout=5)
                    if self.peer_scores.get(ip, 0) < self.PEER_SCORE_CAP:
                        self.peer_scores[ip] += 1
                except Exception:
                    with self.lock:
                        self.peer_scores[ip] = self.peer_scores.get(ip, 10) - 1
                        if self.peer_scores[ip] <= 0:
                            self.peers.discard(ip)
                            self.peer_scores.pop(ip, None)

    def _run_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', P2P_PORT))
            s.listen(100)
            while True:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self._handle_socket_client, args=(conn,), daemon=True).start()
                except Exception as e:
                    logger.error(f"[Server Socket Failure Intercepted] {e}")

    def _handle_socket_client(self, conn):
        with conn:
            try:
                conn.settimeout(5.0)
                data = conn.recv(4096).decode()
                if not data:
                    return
                peer_ip = conn.getpeername()[0]
                self._handle_request(conn, data, peer_ip)
            except Exception:
                pass

    def _handle_request(self, conn, data, peer_ip):
        try:
            req_payload = json.loads(data)
            req_type = req_payload.get("type")

            if req_type in ["peer_request", "gossip_request"]:
                with self.lock:
                    if peer_ip not in self.peers and peer_ip != self.my_ip:
                        self.peers.add(peer_ip)
                        self.peer_scores[peer_ip] = 10
                    peers_to_send = random.sample(list(self.peers), k=min(len(self.peers), 10))
                response = {"status": "ok", "peers": list(peers_to_send)}
                conn.sendall(json.dumps(response).encode())

            elif req_type == "heartbeat":
                with self.lock:
                    if peer_ip not in self.peers and peer_ip != self.my_ip:
                        self.peers.add(peer_ip)
                        self.peer_scores[peer_ip] = 10
                    if self.peer_scores.get(peer_ip, 0) < self.PEER_SCORE_CAP:
                        self.peer_scores[peer_ip] += 1
                conn.sendall(b'{"status": "ok"}')
            else:
                conn.sendall(b'{"status": "error", "message": "Unknown configuration path token"}')
        except Exception:
            conn.sendall(b'{"status": "error", "message": "Malformed connection payload"}')

    def _send_request(self, ip, message, timeout=5):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, P2P_PORT))
            s.sendall(json.dumps(message).encode())
            response_data = s.recv(4096).decode()
            response = json.loads(response_data)
            if response.get("status") == "ok" and "peers" in response:
                with self.lock:
                    for peer in response["peers"]:
                        clean_ip = peer.split(":")[0]
                        if clean_ip not in self.peers and clean_ip != self.my_ip:
                            self.peers.add(clean_ip)
                            self.peer_scores[clean_ip] = 10

# --- State Maintenance and LevelDB Database Helpers ---
def get_balance(addr):
    try:
        addr = Web3.to_checksum_address(addr)
    except Exception:
        return 0
    raw = db.get(f"balance:{addr}".encode())
    return int(raw.decode()) if raw else 0

def set_balance(addr, val):
    addr = Web3.to_checksum_address(addr)
    db.put(f"balance:{addr}".encode(), str(val).encode())

def get_nonce(addr):
    try:
        addr = Web3.to_checksum_address(addr)
    except Exception:
        return 0
    raw = db.get(f"nonce:{addr}".encode())
    last_confirmed_nonce = int(raw.decode()) if raw else -1
    return last_confirmed_nonce + 1

def set_nonce(addr, last_confirmed_nonce):
    addr = Web3.to_checksum_address(addr)
    db.put(f"nonce:{addr}".encode(), str(last_confirmed_nonce).encode())

def decode_raw_transaction(raw_tx):
    try:
        tx_bytes = bytes.fromhex(raw_tx[2:])
        decoded = rlp.decode(tx_bytes, Transaction).as_dict()
        sender = Account.recover_transaction(raw_tx)
        to = Web3.to_checksum_address(decoded['to']) if decoded.get('to') else None
        return {
            "nonce": decoded['nonce'], 
            "gasPrice": hex(decoded['gasPrice']), 
            "gas": hex(decoded['gas']),
            "to": to, 
            "value": hex(decoded['value']), 
            "data": decoded['data'].hex() if isinstance(decoded['data'], bytes) else decoded['data'],
            "from": sender
        }
    except Exception:
        return None

def generate_tx_hash(raw_tx):
    return Web3.keccak(hexstr=raw_tx).hex()

def store_transaction_status(tx_hash, tx_data):
    db.put(f"tx:{tx_hash}".encode(), json.dumps(tx_data).encode())

def update_transaction_to_block(tx_hash, tx_data, block_num, block_hash):
    tx_data['block_number'] = hex(block_num)
    tx_data['blockHash'] = block_hash
    tx_data['status'] = '0x1'
    db.put(f"tx:{tx_hash}".encode(), json.dumps(tx_data).encode())

def get_transaction_by_hash(tx_hash):
    raw = db.get(f"tx:{tx_hash}".encode())
    if raw:
        try:
            return json.loads(raw.decode())
        except Exception:
            return None
    return None

def get_block_by_number(block_num):
    block_data_raw = db.get(f"block:{block_num}".encode())
    return json.loads(block_data_raw.decode()) if block_data_raw else None

def get_block_number_by_hash(block_hash):
    hash_key = block_hash.lower().replace('0x', '')
    raw = db.get(f"hash_to_num:{hash_key}".encode())
    return int(raw.decode()) if raw else None

def get_transaction_receipt_by_hash(tx_hash):
    tx_data = get_transaction_by_hash(tx_hash)
    if not tx_data or tx_data.get('status', 'pending') != '0x1':
        return None

    block_num_hex = tx_data.get('block_number')
    block_hash = tx_data.get('blockHash')
    if not block_num_hex or not block_hash:
        return None

    block_data = get_block_by_number(int(block_num_hex, 16))
    if not block_data:
        return None

    try:
        tx_index = -1
        for i, tx_info_str in enumerate(block_data['transactions']):
            tx = json.loads(tx_info_str)
            if tx.get('hash') == tx_hash:
                tx_index = i
                break
    except Exception:
        return None

    if tx_index == -1:
        return None

    return {
        "transactionHash": tx_hash,
        "transactionIndex": hex(tx_index),
        "blockHash": block_hash,
        "blockNumber": block_num_hex,
        "from": tx_data['from'],
        "to": tx_data.get('to'),
        "gasUsed": tx_data['gasUsed'],
        "effectiveGasPrice": tx_data['effectiveGasPrice'],
        "status": "0x1"
    }

def create_genesis_block():
    genesis_block = {
        "number": "0x0",
        "hash": "0x" + GENESIS_PREV_HASH,
        "parentHash": "0x" + GENESIS_PREV_HASH,
        "transactions": [],
        "timestamp": hex(int(time.time())),
        "nonce": "0x0",
    }
    db.put(b"block:0", json.dumps(genesis_block).encode())
    db.put(b"last_block_hash", genesis_block["hash"].encode())
    db.put(b"last_block_number", b"0")
    db.put(f"hash_to_num:{GENESIS_PREV_HASH.lower()}".encode(), b"0")
    logger.info("[Chain Initialization] Genesis block established.")
    return genesis_block

def get_last_block_info():
    last_block_num_raw = db.get(b"last_block_number")
    last_block_hash_raw = db.get(b"last_block_hash")
    last_block_num = int(last_block_num_raw.decode()) if last_block_num_raw else 0
    last_block_hash = last_block_hash_raw.decode() if last_block_hash_raw else "0x" + GENESIS_PREV_HASH
    return last_block_num, last_block_hash

# --- Network Peer State Integration Sync Engine ---
class ChainSync:
    def __init__(self, peer_manager):
        self.peer_manager = peer_manager

    def get_peer_heights(self):
        peers = self.peer_manager.peers
        peer_heights = {}
        for ip in peers:
            try:
                res = requests.post(f"http://{ip}:{REST_PORT}/", json={"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}, timeout=5)
                if res.status_code == 200:
                    height = int(res.json().get("result", "0x0"), 16)
                    peer_heights[ip] = height
            except Exception:
                pass
        return peer_heights

    def sync_chain(self):
        last_block_num, _ = get_last_block_info()
        peer_heights = self.get_peer_heights()
        if not peer_heights:
            logger.info("[ChainSync] Standalone engine operation detected. Proceeding with local state.")
            return

        longest_chain_ip = max(peer_heights, key=peer_heights.get)
        longest_chain_height = peer_heights[longest_chain_ip]

        if longest_chain_height <= last_block_num:
            return

        logger.info(f"[ChainSync] Downloading blocks from remote node height {last_block_num} -> {longest_chain_height}")
        blocks_to_sync = longest_chain_height - last_block_num
        start_block = last_block_num + 1

        while blocks_to_sync > 0:
            blocks_in_chunk = min(blocks_to_sync, SYNC_THRESHOLD)
            end_block = start_block + blocks_in_chunk - 1
            if not self.download_blocks(longest_chain_ip, start_block, end_block):
                return 

            blocks_to_sync -= blocks_in_chunk
            start_block += blocks_in_chunk

    def download_blocks(self, ip, start_block, end_block):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(30)
                s.connect((ip, BLOCK_DOWNLOAD_PORT))
                s.sendall(f"GET_BLOCKS:{start_block}:{end_block}".encode())

                response = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                blocks = json.loads(response.decode())
                for block in blocks:
                    block_num = int(block['number'], 16)
                    block_hash = block['hash']
  
                    last_block_hash_db = db.get(b"last_block_hash").decode()
                    if block['parentHash'] != last_block_hash_db:
                        return False
  
                    db.put(f"block:{block_num}".encode(), json.dumps(block).encode())
                    db.put(b"last_block_hash", block_hash.encode())
                    db.put(b"last_block_number", str(block_num).encode())
                    db.put(f"hash_to_num:{block_hash.lower().replace('0x', '')}".encode(), str(block_num).encode())

                    for tx_info_str in block['transactions']:
                        tx = json.loads(tx_info_str)
                        sender = tx["from"]
                        receiver = tx["to"]
                        value = int(tx["value"], 16)
                        total_deduction = int(tx['total_cost'], 16)
                        platform_fee = int(tx['platformFee'], 16)

                        set_balance(sender, get_balance(sender) - total_deduction)
                        if receiver:
                            set_balance(receiver, get_balance(receiver) + value)
                        set_nonce(sender, int(tx['nonce'], 16))
                        set_balance(GENESIS_WALLET, get_balance(GENESIS_WALLET) + platform_fee)
                        update_transaction_to_block(tx['hash'], tx, block_num, block_hash)
            return True
        except Exception:
            return False

# --- Transaction Consensus and Asynchronous Core Mining Engine ---
class BlockCreator:
    def __init__(self, peer_manager):
        self.peer_manager = peer_manager
        self.is_running = True

    def run(self):
        while self.is_running:
            time.sleep(10)
            self.create_and_broadcast_block()

    def create_and_broadcast_block(self):
        with confirmed_mempool_lock:
            if not confirmed_mempool:
                return

            txs_for_block = confirmed_mempool[:1000]
            del confirmed_mempool[:len(txs_for_block)]

            last_block_num, last_block_hash = get_last_block_info()
            new_block_num = last_block_num + 1

            for tx in txs_for_block:
                sender = tx["from"]
                receiver = tx["to"]
                value = int(tx["value"], 16)
                total_deduction = int(tx['total_cost'], 16)
                platform_fee = int(tx['platformFee'], 16)
            
                set_balance(sender, get_balance(sender) - total_deduction)
                if receiver:
                    set_balance(receiver, get_balance(receiver) + value)
                set_nonce(sender, int(tx['nonce'], 16))
                set_balance(GENESIS_WALLET, get_balance(GENESIS_WALLET) + platform_fee)

            block_data = {
                "number": hex(new_block_num),
                "parentHash": last_block_hash,
                "transactions": [json.dumps(tx) for tx in txs_for_block],
                "timestamp": hex(int(time.time())),
                "nonce": "0x0"
            }

            block_string = json.dumps(block_data, sort_keys=True)
            block_hash = "0x" + hashlib.sha256(block_string.encode()).hexdigest()
            block_data["hash"] = block_hash

            db.put(f"block:{new_block_num}".encode(), json.dumps(block_data).encode())
            db.put(b"last_block_hash", block_hash.encode())
            db.put(b"last_block_number", str(new_block_num).encode())
            db.put(f"hash_to_num:{block_hash.lower().replace('0x', '')}".encode(), str(new_block_num).encode())

            blockchain_data["blockNumber"] = hex(new_block_num)
            blockchain_data["lastBlockHash"] = block_hash
            logger.info(f"[Mining Engine] Successfully sealed block #{new_block_num}. Packed Tx count: {len(txs_for_block)}")
      
            for tx in txs_for_block:
                update_transaction_to_block(tx['hash'], tx, new_block_num, block_hash)

            self.broadcast_block(block_data)

    def broadcast_block(self, block):
        peers = self.peer_manager.peers
        for ip in peers:
            try:
                s = zmq_context.socket(zmq.REQ)
                s.setsockopt(zmq.LINGER, 0)
                s.connect(f"tcp://{ip}:{SYNC_PORT}")
                s.send_json({"type": "block", "data": block})
                poll = zmq.Poller()
                poll.register(s, zmq.POLLIN)
                if dict(poll.poll(2000)).get(s) == zmq.POLLIN:
                    s.recv_json()
                s.close()
            except Exception:
                pass

def compute_pos_signature(h, sig, ip):
    return hashlib.sha256((h + sig + ip).encode()).hexdigest()

def compute_pov_signature(sig, h):
    return hashlib.sha256((sig + h).encode()).hexdigest()

def add_to_mempool(tx_hash, raw_tx, tx_info, sig):
    with mempool_lock:
        if tx_hash not in mempool:
            mempool[tx_hash] = {"raw_tx": raw_tx, "tx_info": tx_info, "original_signature": sig, "votes": {}, "start_time": time.time()}

def record_vote(tx_hash, validator_id, vote, pov=None):
    with mempool_lock:
        if tx_hash in mempool:
            mempool[tx_hash]["votes"][validator_id] = {"vote": vote, "pov": pov}

def local_vote(tx_info, total_deduction):
    current_expected_nonce = get_nonce(tx_info["from"])
    current_balance = get_balance(tx_info["from"])
    new_tx_nonce = tx_info["nonce"]
    return (new_tx_nonce == current_expected_nonce) and (current_balance >= total_deduction)

def request_vote_zmq(ip, tx_hash, tx_info, sig, total_deduction):
    try:
        s = zmq_context.socket(zmq.REQ)
        s.setsockopt(zmq.LINGER, 0)
        s.connect(f"tcp://{ip}:{VOTE_PORT}")
        s.send_json({"txHash": tx_hash, "tx": tx_info, "total_cost": total_deduction, "meta_data": {"pos_signature": compute_pos_signature(tx_hash, sig, ip)}})
        poll = zmq.Poller()
        poll.register(s, zmq.POLLIN)
        if dict(poll.poll(5000)).get(s) == zmq.POLLIN:
            r = s.recv_json()
            s.close()
            return r.get("status") == "valid", r.get("pov")
        s.close()
        return False, None
    except Exception:
        return False, None

def majority_vote(peer_manager, tx_hash, tx_info, raw_tx, total_deduction):
    sig = raw_tx[130:194]
    ips = peer_manager.peers
    add_to_mempool(tx_hash, raw_tx, tx_info, sig)
    pov = compute_pov_signature(sig, tx_hash)

    record_vote(tx_hash, "local", local_vote(tx_info, total_deduction), pov)

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(request_vote_zmq, ip, tx_hash, tx_info, sig, total_deduction): ip for ip in ips}
        for f in as_completed(futures, timeout=VOTE_TIMEOUT):
            try:
                vote, rpov = f.result()
            except Exception:
                vote, rpov = False, None
            if vote and rpov == pov:
                record_vote(tx_hash, futures[f], vote, rpov)
                
    valid = sum(1 for v in mempool[tx_hash]["votes"].values() if v["vote"])
    required_majority = (len(ips) + 1) // 2
    return valid >= required_majority

def add_confirmed_to_mempool(tx_info, total_deduction, gas_limit, gas_price, platform_fee):
    with confirmed_mempool_lock:
        tx_info['total_cost'] = hex(total_deduction)
        tx_info['gasUsed'] = hex(gas_limit)
        tx_info['effectiveGasPrice'] = hex(gas_price)
        tx_info['platformFee'] = hex(platform_fee)
        tx_info['nonce'] = hex(tx_info['nonce'])
        confirmed_mempool.append(tx_info)

def process_transaction_async(peer_manager, tx_hash, tx_info, raw_tx, total_deduction, gas_limit, gas_price, platform_fee):
    if not majority_vote(peer_manager, tx_hash, tx_info, raw_tx, total_deduction):
        with mempool_lock:
            mempool.pop(tx_hash, None)
        tx_info['status'] = '0x0'
        store_transaction_status(tx_hash, tx_info)
        return

    add_confirmed_to_mempool(tx_info, total_deduction, gas_limit, gas_price, platform_fee)
    with mempool_lock:
        mempool.pop(tx_hash, None)

# --- Sub-Thread Communication Infrastructure Servers ---
def run_vote_zmq():
    s = zmq_context.socket(zmq.REP)
    s.bind(f"tcp://0.0.0.0:{VOTE_PORT}")
    while True:
        try:
            msg = s.recv_json()
            tx_info = msg.get("tx")
            tx_hash = msg.get("txHash")
            total_deduction = msg.get("total_cost")

            if isinstance(tx_info.get("nonce"), str) and tx_info["nonce"].startswith("0x"):
                 tx_info["nonce"] = int(tx_info["nonce"], 16)

            if 'original_signature' not in tx_info:
                s.send_json({"status": "error", "message": "Missing core signature metadata parameters."})
                continue

            if local_vote(tx_info, total_deduction):
                raw_tx = mempool.get(tx_hash, {}).get("raw_tx")
                sig = raw_tx[130:194] if raw_tx else tx_info['original_signature']
                pov = compute_pov_signature(sig, tx_hash)
                s.send_json({"status": "valid", "pov": pov})
            else:
                s.send_json({"status": "invalid", "message": "State requirements check rejected transaction validity rules."})
        except Exception as e:
            s.send_json({"status": "error", "message": str(e)})

def run_sync_zmq():
    s = zmq_context.socket(zmq.REP)
    s.bind(f"tcp://0.0.0.0:{SYNC_PORT}")
    while True:
        try:
            msg = s.recv_json()
            if msg.get("type") == "block":
                block = msg.get("data")
                block_num = int(block['number'], 16)
                block_hash = block['hash']

                last_local_num, last_local_hash = get_last_block_info()
                if block_num == last_local_num + 1 and block['parentHash'] == last_local_hash:
                    db.put(f"block:{block_num}".encode(), json.dumps(block).encode())
                    db.put(b"last_block_hash", block_hash.encode())
                    db.put(b"last_block_number", str(block_num).encode())
                    db.put(f"hash_to_num:{block_hash.lower().replace('0x', '')}".encode(), str(block_num).encode())

                    for tx_info_str in block['transactions']:
                        tx = json.loads(tx_info_str)
                        sender = tx["from"]
                        receiver = tx["to"]
                        value = int(tx["value"], 16)
                        total_deduction = int(tx['total_cost'], 16)
                        platform_fee = int(tx['platformFee'], 16)

                        set_balance(sender, get_balance(sender) - total_deduction)
                        if receiver:
                            set_balance(receiver, get_balance(receiver) + value)
                        set_nonce(sender, int(tx['nonce'], 16))
                        set_balance(GENESIS_WALLET, get_balance(GENESIS_WALLET) + platform_fee)
                        update_transaction_to_block(tx['hash'], tx, block_num, block_hash)
                    s.send_json({"status": "synced"})
                else:
                    s.send_json({"status": "error", "msg": "Out-of-order execution sequence dropped."})
            else:
                s.send_json({"status": "error", "msg": "Invalid structural payload mapping."})
        except Exception as e:
            s.send_json({"status": "error", "msg": str(e)})

def run_block_download_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', BLOCK_DOWNLOAD_PORT))
        s.listen()
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    data = conn.recv(1024).decode()
                    if data.startswith("GET_BLOCKS:"):
                        parts = data.split(':')
                        start_block, end_block = int(parts[1]), int(parts[2])
                        blocks_to_send = []
                        for i in range(start_block, end_block + 1):
                            block = get_block_by_number(i)
                            if block:
                                blocks_to_send.append(block)
                        conn.sendall(json.dumps(blocks_to_send).encode())
            except Exception:
                pass

# --- Full Web3 Engine JSON-RPC Handlers ---
@app.route('/', methods=['POST'])
def rpc():
    try:
        data = request.get_json()
        method = data.get('method')
        params = data.get('params', [])

        if method == 'eth_chainId':
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": blockchain_data["chainId"]})
        elif method == 'eth_blockNumber':
            last_block_num, _ = get_last_block_info()
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": hex(last_block_num)})
        elif method == 'eth_getBalance':
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": hex(get_balance(params[0]))})
        elif method == 'eth_getTransactionCount':
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": hex(get_nonce(params[0]))})
        elif method == 'eth_getTransactionByHash':
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": get_transaction_by_hash(params[0])})
        elif method == 'eth_getTransactionReceipt':
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": get_transaction_receipt_by_hash(params[0])})
        elif method == 'eth_getCode':
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": "0x"})
        elif method == 'eth_getBlockByNumber':
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": get_block_by_number(int(params[0], 16))})
        elif method == 'eth_getBlockByHash':
            block_num = get_block_number_by_hash(params[0]) if params else None
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": get_block_by_number(block_num) if block_num is not None else None})
      
        elif method == 'eth_gasPrice':
            value_wei = 0
            if params and len(params) > 0 and isinstance(params[0], str):
                try:
                    tx_info = decode_raw_transaction(params[0])
                    if tx_info and "value" in tx_info:
                        value_wei = int(tx_info["value"], 16)
                except: pass
            if value_wei == 0:
                value_wei = BASE_UNIT_CONVERSION
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": hex(dynamic_gas_price(value_wei))})
      
        elif method == 'eth_estimateGas':
            value_wei = 0
            if params and len(params) > 0:
                try:
                    value_wei = int(params[0].get('value', '0x0'), 16)
                except: pass
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": hex(dynamic_gas_limit(value_wei))})

        elif method == 'eth_sendRawTransaction':
            raw_tx = params[0] if params else None
            if not raw_tx:
                return jsonify({"jsonrpc": "2.0", "id": data["id"], "error": {"code": -32602, "message": "Missing raw tx entry vector."}})

            try:
                tx_rlp = rlp.decode(bytes.fromhex(raw_tx[2:]), Transaction).as_dict()
                sender = Account.recover_transaction(raw_tx)
                receiver = Web3.to_checksum_address(tx_rlp['to']) if tx_rlp.get('to') else None
                value = int(tx_rlp['value'])
            except Exception as e:
                return jsonify({"jsonrpc": "2.0", "id": data["id"], "error": {"code": -32000, "message": f"Malformed RLP structure: {e}"}})

            new_tx_nonce = tx_rlp['nonce']
            current_expected_nonce = get_nonce(sender)
        
            if new_tx_nonce != current_expected_nonce:
                return jsonify({"jsonrpc": "2.0", "id": data["id"], "error": {"code": -32000, "message": f"Nonce mismatch. Expected: {current_expected_nonce}"}})

            min_fee_in_base_units = BASE_GAS_LIMIT * MIN_GAS_PRICE
            current_balance = get_balance(sender)

            if current_balance < (value + min_fee_in_base_units):
                return jsonify({"jsonrpc": "2.0", "id": data["id"], "error": {"code": -32000, "message": "Insufficient balance under minimal fee projection conditions."}})
           
            platform_fee = calculate_platform_fee(value)
            total_deduction = value + platform_fee

            if current_balance < total_deduction:
                return jsonify({"jsonrpc": "2.0", "id": data["id"], "error": {"code": -32000, "message": "Insufficient liquid balance to clear network transaction platform fee."}})

            gas_limit = dynamic_gas_limit(value)
            gas_price = dynamic_gas_price(value)
            tx_hash = generate_tx_hash(raw_tx)

            with mempool_lock, confirmed_mempool_lock:
                if tx_hash in mempool or any(tx_data["tx_info"]["from"] == sender for tx_data in mempool.values()) or any(tx["from"] == sender for tx in confirmed_mempool):
                    return jsonify({"jsonrpc": "2.0", "id": data["id"], "error": {"code": -32000, "message": "Single-Pending transaction strategy constraint error rule violation."}})

            tx_info = {
                "nonce": new_tx_nonce, 
                "gasPrice": hex(gas_price),
                "gas": hex(gas_limit),
                "to": receiver,
                "value": hex(value),
                "data": tx_rlp['data'].hex() if isinstance(tx_rlp['data'], bytes) else tx_rlp['data'],
                "from": sender,
                "original_signature": raw_tx[130:194], 
                "gasUsed": hex(gas_limit),
                "effectiveGasPrice": hex(gas_price),
                "platformFee": hex(platform_fee),
                "total_cost": hex(total_deduction),
                "hash": tx_hash,
                "status": "pending",
                "block_number": None,
                "blockHash": None
            }

            store_transaction_status(tx_hash, tx_info)
            ASYNC_EXECUTOR.submit(process_transaction_async, peer_manager, tx_hash, tx_info, raw_tx, total_deduction, gas_limit, gas_price, platform_fee)
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "result": tx_hash})
      
        else:
            return jsonify({"jsonrpc": "2.0", "id": data["id"], "error": {"code": -32601, "message": "Method entry point parameter signature signature not matched."}})
    except Exception as e:
        return jsonify({"jsonrpc": "2.0", "error": {"code": -32000, "message": f"Internal execution crash: {e}"}})

if __name__ == '__main__':
    zmq_context = zmq.Context()
    persistence_manager = PeerPersistence()
    
    # Initialize component managers with safe loop routing values
    peer_manager = PeerManager("127.0.0.1", BOOTSTRAP_IPS, persistence_manager)
    chain_sync = ChainSync(peer_manager)
    block_creator = BlockCreator(peer_manager)

    if not db.get(b"last_block_number"):
        create_genesis_block()
        set_balance(GENESIS_WALLET, danic_balance.INITIAL_BALANCE)
        set_nonce(GENESIS_WALLET, -1)

    peer_manager.start()

    Thread(target=run_vote_zmq, daemon=True).start()
    Thread(target=run_sync_zmq, daemon=True).start()
    Thread(target=run_block_download_server, daemon=True).start()
    Thread(target=block_creator.run, daemon=True).start()

    while True:
        try:
            chain_sync.sync_chain()
            break  
        except Exception as e:
            logger.error(f"[Loop Alert] Primary sync engine state recovery retry event triggered: {e}")
            time.sleep(60)

    logger.info("[Production Server Deployment] Running engine services under Waitress gateway profiles.")
    serve(app, host='0.0.0.0', port=8041, threads=4)
