import dash
from dash import dcc, html, Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from scapy.all import rdpcap
import os

LOG_DIR = "logs"
PCAP_FILE = os.path.join(LOG_DIR, "sniffed_packets.pcap")

# Initialize Dash app
app = dash.Dash(__name__)
app.title = "Network Packet Dashboard"

# Layout
app.layout = html.Div([
    html.H1("Network Packet Dashboard", style={'text-align': 'center'}),
    
    dcc.Interval(
        id='interval-component',
        interval=5000,  # Update every 5 seconds
        n_intervals=0
    ),
    
    dcc.Graph(id='packet-frequency'),
    dcc.Graph(id='packet-size-distribution'),
    dcc.Graph(id='protocol-distribution'),
    dcc.Graph(id='top-source-ips')
])

# Callback to update figures dynamically
@app.callback(
    [
        Output('packet-frequency', 'figure'),
        Output('packet-size-distribution', 'figure'),
        Output('protocol-distribution', 'figure'),
        Output('top-source-ips', 'figure')
    ],
    Input('interval-component', 'n_intervals')
)
def update_graphs(n):
    if not os.path.exists(PCAP_FILE):
        return go.Figure(), go.Figure(), go.Figure(), go.Figure()
    
    packets = rdpcap(PCAP_FILE)
    timestamps = [packet.time for packet in packets]
    packet_sizes = [len(packet) for packet in packets]
    protocols = [packet.payload.name for packet in packets]
    src_ips = [packet[1].src for packet in packets if packet.haslayer("IP")]
    
    # Packet Frequency
    freq_fig = px.histogram(x=timestamps, nbins=15, labels={'x': 'Time', 'y': 'Packet Count'}, title="Packet Frequency Over Time")
    
    # Packet Size Distribution
    size_fig = px.histogram(x=packet_sizes, nbins=15, labels={'x': 'Packet Size (Bytes)', 'y': 'Frequency'}, title="Packet Size Distribution")
    
    # Protocol Distribution
    protocol_counts = pd.Series(protocols).value_counts()
    protocol_fig = px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Protocol Distribution")
    
    # Top Source IPs
    src_ip_counts = pd.Series(src_ips).value_counts().nlargest(5)
    src_ip_fig = px.bar(x=src_ip_counts.index, y=src_ip_counts.values, labels={'x': 'Source IPs', 'y': 'Packet Count'}, title="Top 5 Source IPs")
    
    return freq_fig, size_fig, protocol_fig, src_ip_fig

if __name__ == '__main__':
    app.run(debug=True)

