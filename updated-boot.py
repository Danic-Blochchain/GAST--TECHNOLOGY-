import json
import logging
import random
import socket
import threading
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify

# --- Configuration ---
P2P_PORT = 8000              # Raw P2P TCP socket port
REST_PORT = 8041             # Secure HTTP Discovery & Handshake port
GOSSIP_INTERVAL = 60         # Seconds between neighbor state shares
HEARTBEAT_TIMEOUT = 10       # Seconds between node health checks
BOOTSTRAP_IPS = []           # Hardcoded fallback seed nodes if applicable

# Sovereign Network Access Token
DANIC_GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("DANIC_BOOTSTRAP")

class PeerPersistence:
    def __init__(self, filename='last_active_peers.json'):
        self.filename = filename
        self.lock = threading.Lock()

    def save_peers(self, peers):
        with self.lock:
            try:
                with open(self.filename, 'w') as f:
                    json.dump(list(peers), f, indent=4)
                logger.info(f"[Persistence] Archived {len(peers)} active peer configurations to local directory.")
            except Exception as e:
                logger.error(f"[Persistence Error] Could not write peer map to disk: {e}")

    def load_peers(self):
        with self.lock:
            try:
                with open(self.filename, 'r') as f:
                    peers = set(json.load(f))
                logger.info(f"[Persistence] Restored {len(peers)} tracked nodes from disk record storage.")
                return peers
            except FileNotFoundError:
                logger.warning("[Persistence] No prior node metadata database located. Initializing clean ledger.")
                return set()
            except Exception as e:
                logger.error(f"[Persistence Error] Disk load corruption encountered: {e}")
                return set()

class BootstrapNode:
    def __init__(self, bootstrap_ips):
        self.bootstrap_ips = set(bootstrap_ips)
        self.peers = set()
        self.peer_scores = {}
        self.lock = threading.Lock()
        self.PEER_SCORE_CAP = 20

        self.persistence_manager = PeerPersistence()
        self.flask_app = Flask("DanicReflector")
        self._configure_endpoints()

        self.gossip_thread = threading.Thread(target=self._gossip_loop, daemon=True)
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.tcp_server_thread = threading.Thread(target=self._run_tcp_server, daemon=True)
        self.rest_server_thread = threading.Thread(target=self._run_rest_server, daemon=True)

    def start(self):
        """Spawns all asynchronous communication vectors simultaneously."""
        self.tcp_server_thread.start()
        self.gossip_thread.start()
        self.heartbeat_thread.start()
        self.rest_server_thread.start()
        logger.info("[Engine] All raw network protocols and validation listener sub-channels online.")
        self.run_discovery_sequence()

    def _configure_endpoints(self):
        """Implements Approach 2: Two-Step Secure Network Admission."""
        
        @self.flask_app.route('/discover', methods=['GET'])
        def discover():
            """STEP 1: PASSIVE REFLECTION - Evaluates caller's public IP from the transport frame."""
            if request.headers.get('X-Forwarded-For'):
                client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            else:
                client_ip = request.remote_addr
            logger.info(f"[Reflector] Safely mirrored isolated connection fingerprint for node: {client_ip}")
            return jsonify({"status": "SUCCESS", "your_ip": client_ip})

        @self.flask_app.route('/peer-handshake', methods=['POST'])
        def secure_handshake():
            """STEP 2: INTENTIONAL GENESIS REGISTRATION - Validates token signatures before admission."""
            data = request.get_json() or {}
            client_genesis_hash = data.get("genesis_hash")
            client_reflected_ip = data.get("peer_ip")
            client_p2p_port = data.get("p2p_port", P2P_PORT)

            if not client_genesis_hash or client_genesis_hash.strip() != DANIC_GENESIS_HASH:
                logger.warning(f"[SECURITY] Blocked unauthenticated connection attempt from host: {request.remote_addr}")
                return jsonify({"status": "REJECTED", "reason": "Sovereign network genesis signature mismatch."}), 401

            if not client_reflected_ip:
                return jsonify({"status": "REJECTED", "reason": "Missing validated client connection identifier."}), 400

            node_endpoint = f"{client_reflected_ip}:{client_p2p_port}"

            with self.lock:
                if node_endpoint not in self.peers:
                    self.peers.add(node_endpoint)
                self.peer_scores[node_endpoint] = self.PEER_SCORE_CAP
                
                # Filter healthy peers for discovery routing
                active_nodes = [node for node in self.peers if self.peer_scores.get(node, 0) > 10]
                sampling_size = min(len(active_nodes), 200)
                optimized_peer_batch = random.sample(active_nodes, k=sampling_size)

            logger.info(f"[Registry] Node {node_endpoint} verified via Genesis signature check. Active Nodes: {len(active_nodes)}")
            return jsonify({
                "status": "SUCCESS",
                "active_peer_count": len(active_nodes),
                "active_peers": optimized_peer_batch
            })

    def _run_rest_server(self):
        import os
        os.environ["WERKZEUG_RUN_MAIN"] = "true"
        self.flask_app.run(host='0.0.0.0', port=REST_PORT, debug=False, threaded=True)

    def run_discovery_sequence(self):
        logger.info("[P2P Loop] Querying default cluster routes...")
        success = self.attempt_connection_in_parallel(self.bootstrap_ips)
        if not success:
            loaded_peers = self.persistence_manager.load_peers()
            self.attempt_connection_in_parallel(loaded_peers)

    def attempt_connection_in_parallel(self, ips_to_try):
        if not ips_to_try:
            return False
        successful_connection = False
        with ThreadPoolExecutor(max_workers=min(len(ips_to_try), 10)) as executor:
            future_to_ip = {
                executor.submit(self._send_request, ip, {"type": "peer_request"}): ip
                for ip in ips_to_try
            }
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    future.result()
                    with self.lock:
                        self.peers.add(ip)
                        self.peer_scores[ip] = 10
                    logger.info(f"[P2P Socket] Synchronized state map with seed host: {ip}.")
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
                except Exception as e:
                    logger.warning(f"[Gossip Profile] Neighbor state frame drop at destination {ip}: {e}")

            logger.info(f"[Gossip Profile] Cycle complete. Active peer matrix listings: {len(self.peers)}")
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
                except:
                    with self.lock:
                        self.peer_scores[ip] = self.peer_scores.get(ip, 10) - 1
                        if self.peer_scores[ip] <= 0:
                            self.peers.discard(ip)
                            self.peer_scores.pop(ip, None)
                            logger.info(f"[Health Node Tracker] Pruned dead peer from matrix maps: {ip}")

    def _run_tcp_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', P2P_PORT))
            s.listen(100)
            logger.info(f"[Raw TCP] Processing engine listener bound to port {P2P_PORT}")
            while True:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self._handle_socket_client, args=(conn, addr), daemon=True).start()
                except Exception as e:
                    logger.error(f"[TCP Server Engine Crash Recovery] {e}")

    def _handle_socket_client(self, conn, addr):
        with conn:
            try:
                conn.settimeout(5.0)
                data = conn.recv(4096).decode()
                if not data:
                    return
                self._handle_request(conn, data, addr[0])
            except Exception:
                pass

    def _handle_request(self, conn, data, peer_ip):
        try:
            req_data = json.loads(data)
            req_type = req_data.get("type")
            if req_type in ["peer_request", "gossip_request", "heartbeat"]:
                with self.lock:
                    is_verified = any(peer_ip in peer for peer in self.peers)
                    if is_verified:
                        peers_to_send = random.sample(list(self.peers), k=min(len(self.peers), 10))
                        conn.sendall(json.dumps({"status": "ok", "peers": peers_to_send}).encode())
                    else:
                        conn.sendall(b'{"status":"error","message":"Node unauthenticated. Run HTTP Genesis Handshake first."}')
            else:
                conn.sendall(b'{"status":"error","message":"Unknown structural payload protocol code."}')
        except Exception:
            conn.sendall(b'{"status":"error","message":"Internal Server processing exception."}')

    def _send_request(self, target_endpoint, message, timeout=5):
        try:
            ip = target_endpoint.split(":")[0]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, P2P_PORT))
                s.sendall(json.dumps(message).encode())
                response_data = s.recv(4096).decode()
                response = json.loads(response_data)
                if "peers" in response:
                    with self.lock:
                        for peer in response["peers"]:
                            if peer not in self.peers:
                                self.peers.add(peer)
                                self.peer_scores[peer] = 10
        except Exception:
            raise Exception("Target node dropped connection channel connection parameters.")

if __name__ == "__main__":
    bootstrap = BootstrapNode(BOOTSTRAP_IPS)
    bootstrap.start()
    while True:
        time.sleep(3600)
