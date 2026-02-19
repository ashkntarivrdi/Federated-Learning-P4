#!/usr/bin/env python3
import os
import struct
from collections import defaultdict

import matplotlib.pyplot as plt
from scapy.utils import RawPcapReader


# Hardcoded input PCAP files (edit these paths if your files are elsewhere)
PCAP_FILES = [
    "./pcap_10/s1-eth1_in.pcap",
    "./pcap_10/s1-eth2_in.pcap",
    "./pcap_10/s1-eth3_in.pcap",
]

# Hardcoded output image path
OUTPUT_PLOT = "./results/packets_per_epoch.png"

# Project protocol constants
ETH_TYPE_AGGREGATION = 0x1234
ETH_HEADER_LEN = 14
AGG_HEADER_LEN = 10  # round_id, worker_id, chunk_id, total_chunks, chunk_len


def count_packets_per_round(pcap_paths):
    counts = defaultdict(int)

    for pcap_path in pcap_paths:
        for pkt_data, _ in RawPcapReader(pcap_path):
            if len(pkt_data) < ETH_HEADER_LEN + AGG_HEADER_LEN:
                continue

            ether_type = struct.unpack("!H", pkt_data[12:14])[0]
            if ether_type != ETH_TYPE_AGGREGATION:
                continue

            agg = pkt_data[ETH_HEADER_LEN:ETH_HEADER_LEN + AGG_HEADER_LEN]
            round_id, worker_id, chunk_id, total_chunks, chunk_len = struct.unpack("!HHHHH", agg)

            # Count every transmitted aggregation packet.
            counts[round_id] += 1

    return counts


def main():
    os.makedirs(os.path.dirname(OUTPUT_PLOT), exist_ok=True)
    counts = count_packets_per_round(PCAP_FILES)
    if not counts:
        raise RuntimeError("No aggregation packets found. Check PCAP paths/files.")

    round_ids = sorted(counts.keys())
    epochs = [rid + 1 for rid in round_ids]  # round_id in packets is 0-based
    packet_counts = [counts[rid] for rid in round_ids]

    plt.figure(figsize=(9, 5))
    plt.plot(epochs, packet_counts, marker="o", linewidth=2)
    plt.title("Total Broadcast Packets per Epoch")
    plt.xlabel("Epoch")
    plt.ylabel("Total Packets")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.xticks(epochs)
    plt.yticks(range(120, max(packet_counts) + 70, max(1, max(packet_counts) // 10)))
    plt.savefig(OUTPUT_PLOT, dpi=150)

    print("Saved plot to:", OUTPUT_PLOT)


if __name__ == "__main__":
    main()
