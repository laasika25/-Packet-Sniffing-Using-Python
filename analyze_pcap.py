from scapy.all import rdpcap

# Read packets
packets = rdpcap("logs/sniffed_packets.pcap")

# Count and print statistics
print(f"Total packets captured: {len(packets)}")

# Print first 5 packets
for i, packet in enumerate(packets[:5]):
    print(f"Packet {i+1}: {packet.summary()}")
