import argparse
import sys
import threading
import time
from typing import Dict

import numpy as np
from scapy.all import Ether, IP, UDP, Raw, get_if_hwaddr, sendp, sniff
from scapy.packet import Packet

from config.config import AppConfig, load_config
from ml.data_loader import load_multi_mnist
from ml.model import SimpleNeuralNetwork
from protocol.layers import Aggregation, TYPE_AGGREGATION
from utils.network import get_if
from utils.tracker import ResultsTracker

HOSTS = {
    1: {"ip": "10.0.1.1", "mac": "00:00:00:00:01:01", "gw_mac": "00:00:00:00:00:01"},
    2: {"ip": "10.0.1.2", "mac": "00:00:00:00:01:02", "gw_mac": "00:00:00:00:00:02"},
    3: {"ip": "10.0.1.3", "mac": "00:00:00:00:01:03", "gw_mac": "00:00:00:00:00:03"},
}

CHUNK_SIZE = 20
WEIGHT_SCALE = 10000
INTER_PACKET_GAP_SEC = 0.001
# Fixed redundancy keeps packet count equal for every worker in every round.
REDUNDANCY_FACTOR = 2
# Let slower workers finish local training before anybody starts sending.
PRE_SEND_BARRIER_SEC = 5
AGGREGATION_WAIT_TIMEOUT_SEC = 120


class Worker:
    def __init__(self, worker_id: int, config: AppConfig):
        self.worker_id = worker_id
        self.config = config

        self.bitmap_position = 2 ** (worker_id - 1)
        self.iface = get_if()

        self.results_tracker = ResultsTracker(worker_id)
        self.model = SimpleNeuralNetwork(
            input_size=self.config.model_params.input_size,
            hidden_size=self.config.model_params.hidden_size,
            output_size=self.config.model_params.output_size
        )

        if worker_id not in HOSTS:
            raise ValueError(f"Unknown worker_id {worker_id}. Update HOSTS mapping.")
        self.host_info = HOSTS[worker_id]
        self.src_mac = get_if_hwaddr(self.iface)

        self.received_weights: Dict[int, np.ndarray] = {}
        self.pending_chunks: Dict[int, Dict[str, Dict[int, np.ndarray]]] = {}
        self.rx_lock = threading.Lock()
        self.received_event = threading.Event()
        self.current_round = 0

        self.receiver_thread = threading.Thread(target=self._packet_receiver, daemon=True)
        self.receiver_thread.start()

    def _packet_receiver(self):
        print(f"Starting packet receiver on {self.iface}...")
        try:
            sniff(
                filter="ether proto 0x1234",
                iface=self.iface,
                prn=self._handle_packet,
                store=False
            )
        except Exception as e:
            print(f"Error in packet receiver: {e}", file=sys.stderr)

    def _handle_packet(self, pkt: Packet):
        if Aggregation not in pkt or UDP not in pkt:
            return

        agg = pkt[Aggregation]
        round_id = int(agg.round_id)
        sender_id = int(agg.worker_id)
        if round_id != self.current_round or sender_id == self.worker_id:
            return

        chunk_id = int(agg.chunk_id)
        total_chunks = int(agg.total_chunks)
        chunk_len = int(agg.chunk_len)

        payload = bytes(pkt[UDP].payload)
        if not payload:
            return
        if len(payload) % 4 != 0:
            return
        if chunk_len <= 0 or chunk_len > CHUNK_SIZE:
            return

        chunk_data = np.frombuffer(payload, dtype=np.int32)[:chunk_len].astype(np.float32) / WEIGHT_SCALE

        with self.rx_lock:
            info = self.pending_chunks.setdefault(
                sender_id, {"total_chunks": total_chunks, "chunks": {}}
            )
            if info["total_chunks"] != total_chunks:
                info["total_chunks"] = total_chunks
                info["chunks"] = {}

            info["chunks"][chunk_id] = chunk_data

            if len(info["chunks"]) == info["total_chunks"] and sender_id not in self.received_weights:
                ordered = [info["chunks"][i] for i in range(info["total_chunks"])]
                full_weights = np.concatenate(ordered)
                self.received_weights[sender_id] = full_weights
                del self.pending_chunks[sender_id]
                print(
                    f"Round {self.current_round + 1}: received full model from worker {sender_id}. "
                    f"Progress {len(self.received_weights)}/{self.config.protocol.num_workers - 1}"
                )

            if len(self.received_weights) == self.config.protocol.num_workers - 1:
                all_weights = [self.model.get_weights()] + list(self.received_weights.values())
                aggregated = np.mean(np.stack(all_weights, axis=0), axis=0)
                self.model.set_weights(aggregated)
                self.received_event.set()

    def send_model_weights(self):
        weights = self.model.get_weights()
        scaled = np.round(weights * WEIGHT_SCALE).astype(np.int32)
        total_elems = scaled.size
        total_chunks = int(np.ceil(total_elems / CHUNK_SIZE))
        total_packets = (self.config.protocol.num_workers - 1) * total_chunks * REDUNDANCY_FACTOR
        print(
            f"Round {self.current_round + 1}: sending {total_chunks} chunks/peer, "
            f"redundancy={REDUNDANCY_FACTOR}, total_packets={total_packets}"
        )

        for peer_id, peer_info in HOSTS.items():
            if peer_id == self.worker_id:
                continue
            for _ in range(REDUNDANCY_FACTOR):
                for chunk_id in range(total_chunks):
                    start = chunk_id * CHUNK_SIZE
                    end = min(start + CHUNK_SIZE, total_elems)
                    chunk = scaled[start:end]
                    chunk_len = end - start
                    if chunk_len < CHUNK_SIZE:
                        chunk = np.pad(chunk, (0, CHUNK_SIZE - chunk_len), mode="constant")

                    pkt = (
                        Ether(src=self.src_mac, dst=self.host_info["gw_mac"], type=TYPE_AGGREGATION)
                        / Aggregation(
                            round_id=self.current_round,
                            worker_id=self.worker_id,
                            chunk_id=chunk_id,
                            total_chunks=total_chunks,
                            chunk_len=chunk_len,
                        )
                        / IP(src=self.host_info["ip"], dst=peer_info["ip"])
                        / UDP(sport=4000 + self.worker_id, dport=4000 + peer_id)
                        / Raw(load=chunk.tobytes())
                    )
                    sendp(pkt, iface=self.iface, verbose=False)
                    time.sleep(INTER_PACKET_GAP_SEC)

    def run_training_round(self):
        print(f"Loading data for round {self.current_round + 1}...")
        (X_train, y_train), (X_test, y_test) = load_multi_mnist(
            digits=[1, 2, 3],
            num_features=self.config.model_params.input_size,
            num_samples=self.config.training.samples_per_worker,
            num_workers=self.config.protocol.num_workers
        )

        print(f"Training on {len(X_train)} samples...")
        self.model.train(
            X_train, y_train,
            epochs=self.config.training.epochs_per_round,
            learning_rate=self.config.training.learning_rate,
            momentum=self.config.training.momentum
        )

        y_pred_probs = self.model.forward(X_train)
        y_one_hot = np.eye(self.config.model_params.output_size)[y_train]
        loss = self.model.compute_loss(y_one_hot, y_pred_probs)
        train_acc = self.model.evaluate(X_train, y_train)
        self.results_tracker.add_round_results(self.current_round, loss, train_acc)
        print(f"Round {self.current_round + 1} - Pre-aggregation training accuracy: {train_acc:.4f}")
        print(f"Round {self.current_round + 1}: waiting {PRE_SEND_BARRIER_SEC}s barrier before send")
        time.sleep(PRE_SEND_BARRIER_SEC)
        self.send_model_weights()
        print("Waiting for aggregated model from server...")
        if not self.received_event.wait(timeout=AGGREGATION_WAIT_TIMEOUT_SEC):
            with self.rx_lock:
                missing_workers = [
                    wid for wid in HOSTS if wid != self.worker_id and wid not in self.received_weights
                ]
                chunk_progress = {
                    wid: len(state["chunks"]) for wid, state in self.pending_chunks.items()
                }
            raise TimeoutError(
                f"Round {self.current_round + 1} aggregation timeout after "
                f"{AGGREGATION_WAIT_TIMEOUT_SEC}s. Missing workers: {missing_workers}, "
                f"chunk progress: {chunk_progress}"
            )
        post_acc = self.model.evaluate(X_test, y_test)
        print(f"Round {self.current_round + 1} - Post-aggregation test accuracy: {post_acc:.4f}\n")

    def start(self):
        num_rounds = self.config.training.rounds
        for r in range(num_rounds):
            self.current_round = r
            print(f"\n{'=' * 15} Round {r + 1}/{num_rounds} {'=' * 15}")

            with self.rx_lock:
                self.received_weights.clear()
                self.pending_chunks.clear()
                self.received_event.clear()

            self.run_training_round()
            time.sleep(2)

        self.results_tracker.save_to_file()
        print("\nAll training rounds complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Federated Learning Worker Node')
    parser.add_argument('worker_id', type=int, help='Worker ID (1-indexed)')
    parser.add_argument('--config', type=str, default='config/config.json', help='Path to the configuration file')
    args = parser.parse_args()

    try:
        app_config = load_config(args.config)
    except (FileNotFoundError, KeyError, TypeError):
        sys.exit(1)

    np.random.seed(42 + args.worker_id)

    worker = Worker(worker_id=args.worker_id, config=app_config)
    worker.start()
