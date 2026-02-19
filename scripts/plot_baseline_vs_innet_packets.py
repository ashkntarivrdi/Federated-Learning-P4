#!/usr/bin/env python3
import os
import struct
from collections import defaultdict

import matplotlib.pyplot as plt
from scapy.utils import RawPcapReader


# Hardcoded directories
BASELINE_PCAP_DIR = "./pcap_baseline"
INNET_PCAP_DIR = "./pcap_innet"

# Hardcoded output
OUTPUT_PLOT = "./results/baseline_vs_innet_packets_per_epoch.png"

# Protocol constants
ETH_TYPE_AGGREGATION = 0x1234
ETH_HEADER_LEN = 14
AGG_COMMON_HEADER_LEN = 10  # round_id, worker_id, chunk_id, total_chunks, chunk_len


def list_pcap_files(directory):
    return sorted(
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.endswith("_in.pcap")
    )


def count_packets_per_epoch(pcap_files):
    counts = defaultdict(int)

    for pcap_path in pcap_files:
        for pkt_data, _ in RawPcapReader(pcap_path):
            if len(pkt_data) < ETH_HEADER_LEN + AGG_COMMON_HEADER_LEN:
                continue

            ether_type = struct.unpack("!H", pkt_data[12:14])[0]
            if ether_type != ETH_TYPE_AGGREGATION:
                continue

            agg_hdr = pkt_data[ETH_HEADER_LEN:ETH_HEADER_LEN + AGG_COMMON_HEADER_LEN]
            round_id, _, _, _, _ = struct.unpack("!HHHHH", agg_hdr)
            counts[round_id + 1] += 1  # epoch = round_id + 1

    return counts


def to_aligned_series(base_counts, innet_counts):
    epochs = sorted(set(base_counts.keys()) | set(innet_counts.keys()))
    baseline_vals = [base_counts.get(e, 0) for e in epochs]
    innet_vals = [innet_counts.get(e, 0) for e in epochs]
    return epochs, baseline_vals, innet_vals


def main():
    os.makedirs(os.path.dirname(OUTPUT_PLOT), exist_ok=True)

    baseline_pcaps = list_pcap_files(BASELINE_PCAP_DIR)
    innet_pcaps = list_pcap_files(INNET_PCAP_DIR)

    if not baseline_pcaps:
        raise RuntimeError(f"No .pcap files found in {BASELINE_PCAP_DIR}")
    if not innet_pcaps:
        raise RuntimeError(f"No .pcap files found in {INNET_PCAP_DIR}")

    baseline_counts = count_packets_per_epoch(baseline_pcaps)
    innet_counts = count_packets_per_epoch(innet_pcaps)

    if not baseline_counts:
        raise RuntimeError("No aggregation packets found in baseline pcaps.")
    if not innet_counts:
        raise RuntimeError("No aggregation packets found in in-network pcaps.")

    epochs, baseline_vals, innet_vals = to_aligned_series(baseline_counts, innet_counts)

    plt.figure(figsize=(10, 5))
    plt.plot(epochs, baseline_vals, marker="o", linewidth=2, label="Baseline (Host2Host)")
    plt.plot(epochs, innet_vals, marker="s", linewidth=2, label="In-network Aggregation")
    plt.title("Total Broadcast Packets per Epoch: Baseline vs In-network")
    plt.xlabel("Epoch")
    plt.ylabel("Total Packets")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.xticks(epochs)
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUTPUT_PLOT, dpi=150)
    
    print("Saved plot to:", OUTPUT_PLOT)


if __name__ == "__main__":
    main()
