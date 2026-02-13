import matplotlib.pyplot as plt
from scapy.all import rdpcap

# Load packets
packets = rdpcap("logs/sniffed_packets.pcap")

# Extract useful parameters
timestamps = [packet.time for packet in packets]
packet_sizes = [len(packet) for packet in packets]  # Packet size in bytes
protocols = [packet.payload.name for packet in packets]  # Protocol type (IP, ARP, etc.)
src_ips = [packet[1].src for packet in packets if packet.haslayer("IP")]  # Source IPs
dst_ips = [packet[1].dst for packet in packets if packet.haslayer("IP")]  # Destination IPs

# Create subplots
fig, axs = plt.subplots(2, 2, figsize=(12, 10))

# 1️⃣ Packet Frequency Over Time
axs[0, 0].hist(timestamps, bins=15, edgecolor="black")
axs[0, 0].set_xlabel("Time")
axs[0, 0].set_ylabel("Packet Count")
axs[0, 0].set_title("Packet Frequency Over Time")

# 2️⃣ Packet Sizes Distribution
axs[0, 1].hist(packet_sizes, bins=15, color="green", edgecolor="black")
axs[0, 1].set_xlabel("Packet Size (Bytes)")
axs[0, 1].set_ylabel("Frequency")
axs[0, 1].set_title("Packet Size Distribution")

# 3️⃣ Protocol Distribution (Pie Chart)
protocol_counts = {p: protocols.count(p) for p in set(protocols)}
axs[1, 0].pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct="%1.1f%%", startangle=140)
axs[1, 0].set_title("Protocol Distribution")

# 4️⃣ Top 5 Source IPs (Bar Chart)
src_ip_counts = {ip: src_ips.count(ip) for ip in set(src_ips)}
top_src_ips = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
axs[1, 1].bar([ip[0] for ip in top_src_ips], [ip[1] for ip in top_src_ips], color="orange")
axs[1, 1].set_xlabel("Source IPs")
axs[1, 1].set_ylabel("Packet Count")
axs[1, 1].set_title("Top 5 Source IPs")
axs[1, 1].tick_params(axis="x", rotation=45)

plt.tight_layout()
plt.show()
