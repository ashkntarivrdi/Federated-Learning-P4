from scapy.all import Packet, Ether, IP, bind_layers
from scapy.fields import BitField

# Constants to match P4
TYPE_IPV4 = 0x800
TYPE_AGGREGATION = 0x1234

class Aggregation(Packet):
    name = "Aggregation"
    fields_desc = [
        BitField("round_id", 0, 16),
        BitField("worker_id", 0, 16),
        BitField("chunk_id", 0, 16),
        BitField("total_chunks", 0, 16),
        BitField("chunk_len", 0, 16),
    ]


bind_layers(Ether, Aggregation, type=TYPE_AGGREGATION)
bind_layers(Ether, IP, type=TYPE_IPV4)
bind_layers(Aggregation, IP)
