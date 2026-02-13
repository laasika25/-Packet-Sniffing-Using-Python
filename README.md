
# 📡 Network Traffic Analyzer & Visualizer

This project analyzes network traffic from a `.pcap` file using **Scapy** and visualizes key insights with **Matplotlib**.  
It helps in understanding packet distribution, source activity, and protocol usage.

## 🛠️ Tech Stack

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/) [![Scapy](https://img.shields.io/badge/Scapy-000000?style=for-the-badge&logo=python&logoColor=white)](https://scapy.net/) [![Matplotlib](https://img.shields.io/badge/Matplotlib-F9771E?style=for-the-badge&logo=matplotlib&logoColor=white)](https://matplotlib.org/) [![Wireshark](https://img.shields.io/badge/Wireshark-0056B8?style=for-the-badge&logo=wireshark&logoColor=white)](https://www.wireshark.org/) [![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/)


## 📂 Project Structure
```
/packet-sniffer
│── /logs
│ ├── sniffed_packets.pcap # Captured network traffic in PCAP format
│ ├── sniffed_packets.txt # Extracted packet details in text format
│── main.py # Main script to run the packet sniffer
│── analyze_pcap.py # Script to analyze the pcap file
│── visualize_pcap.py # Script to visualize network traffic from pcap file
│── packet_utils.py # Utility functions for packet processing
│── requirements.txt # Dependencies list
│── Figure_1.png # Sample visualization output
│── /pycache/ # Python cache directory (auto-generated)
```
## 📊 Visualizations

| Visualization              | Description                             |
|----------------------------|---------------------------------------|
| Packet Frequency Over Time  | Shows packet density over time         |
| Packet Size Distribution    | Analyzes variation in packet sizes     |
| Protocol Usage (Pie Chart)  | Displays percentage of TCP, UDP, ARP, etc. |
| Top Source IPs (Bar Graph)  | Highlights most active source IPs      |

---

## 🔮 Future Enhancements

- 🚨 Suspicious IP detection  
- 📈 Anomaly detection using Machine Learning  
- 🌐 Live packet capture visualization  
