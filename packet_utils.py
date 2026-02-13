from scapy.all import sniff, wrpcap
import os

LOG_DIR = "logs"
PCAP_FILE = os.path.join(LOG_DIR, "sniffed_packets.pcap")
TXT_FILE = os.path.join(LOG_DIR, "sniffed_packets.txt")

# Ensure logs directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# List to store packets for PCAP file
captured_packets = []

def packet_handler(packet):
    """Handles each captured packet"""
    captured_packets.append(packet)  # Store packet in memory

    # Log human-readable summary
    with open(TXT_FILE, "a") as f:
        f.write(packet.summary() + "\n")

    print(packet.summary())  # Print to console for real-time monitoring

def start_sniffing(interface=None, packet_count=50):
    """
    Starts packet sniffing:
    - If 'interface' is None, captures on any available network.
    - Captures 'packet_count' packets.
    - Saves packets to PCAP and logs details in TXT.
    """
    print(f"[*] Capturing {packet_count} packets...")
    sniff(count=packet_count, prn=packet_handler, iface=interface)

    # Save all packets to PCAP after sniffing is complete
    if captured_packets:
        wrpcap(PCAP_FILE, captured_packets)
        print(f"[+] Packets saved to {PCAP_FILE}")
    else:
        print("[!] No packets captured.")

    print(f"[+] Packet log saved to {TXT_FILE}")
