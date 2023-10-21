from scapy.all import *
from scapy.layers.inet import TCP, IP

failed_login_attempts = {}

"""
Simple SSH intrusion packet analyzer
"""
def analyze_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    logging.basicConfig(filename='/activity.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    log_message = f"Source IP: {src_ip} -> Destination IP: {dst_ip}, Source Port: {src_port} -> Destination Port: {dst_port}"
    print(log_message)
    logging.info(log_message)

    # Detect SSH failed login attempts
    if dst_port == 22:
        if packet[TCP].flags == 'R':
            if src_ip in failed_login_attempts:
                failed_login_attempts[src_ip] += 1
            else:
                failed_login_attempts[src_ip] = 1

            if failed_login_attempts[src_ip] > 3:
                alert_message = f"ALERT: Multiple failed SSH login attempts from {src_ip}"
                print(alert_message)
                logging.warning(alert_message)


# Capture only TCP packets
sniff(filter="tcp", prn=analyze_packet)
