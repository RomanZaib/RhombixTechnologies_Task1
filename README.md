# RhombixTechnologies_Task1
BASIC NETWORK SNIFFER

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    """Callback function to handle captured packets."""
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        
        # Check if it's a TCP packet
        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport  # Source port
            dport = packet[TCP].dport  # Destination port
        # Check if it's a UDP packet
        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            protocol = "Other"
            sport = dport = "N/A"

        # Print the packet details
        print(f"[{protocol}] {ip_src}:{sport} -> {ip_dst}:{dport}")
    else:
        print("Non-IP packet captured.")

# Start sniffing
def start_sniffer(interface=None, packet_count=10):
    """
    Start the sniffer on a specified interface and capture packets.

    Parameters:
    - interface (str): The network interface to sniff on (e.g., 'eth0', 'wlan0').
    - packet_count (int): Number of packets to capture.
    """
    print(f"Starting sniffer on interface: {interface or 'default'}...")
    sniff(iface=interface, prn=packet_callback, count=packet_count)
    print("Sniffing complete.")

# Main function
if __name__ == "__main__":
    # Modify interface and packet_count as needed
    network_interface = None  # Replace with 'eth0', 'wlan0', etc., or leave as None for the default interface
    packets_to_capture = 10   # Set the number of packets to capture

    start_sniffer(interface=network_interface, packet_count=packets_to_capture)

print(f"Packet: {packet.summary()}")
print(f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}")

try:
    if IP in packet:
        print(f"Captured Packet: {packet.summary()}")
except Exception as e:
    print(f"Error processing packet: {e}")

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def packet_callback(packet):
    logging.info(f"Packet: {packet.summary()}")

sniff(iface="eth0", prn=packet_callback, count=10)

from scapy.all import get_if_list
print(get_if_list())


