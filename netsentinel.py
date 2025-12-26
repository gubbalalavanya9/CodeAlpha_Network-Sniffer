from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

# STEP 1: Load PCAP file (offline analysis)
try:
    packets = rdpcap("sample.pcap")
except FileNotFoundError:
    print("ERROR: sample.pcap file not found.")
    exit()

print(f"Total packets loaded: {len(packets)}")

# STEP 2: Initialize data structures
packet_count = defaultdict(int)
port_usage = defaultdict(set)
alerts = []

# STEP 3: Analyze packets
for pkt in packets:
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        packet_count[src_ip] += 1

        if pkt.haslayer(TCP):
            port_usage[src_ip].add(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            port_usage[src_ip].add(pkt[UDP].dport)

# STEP 4: Threat scoring logic
for ip in packet_count:
    threat_score = 0

    if packet_count[ip] > 50:
        threat_score += 20

    if len(port_usage[ip]) > 10:
        threat_score += 30

    if threat_score >= 30:
        alert = f"Suspicious activity detected from {ip} | Threat Score: {threat_score}"
        alerts.append(alert)
        print(alert)

# STEP 5: Generate security report
with open("security_report.txt", "w") as report:
    report.write("NetSentinel Security Report\n")
    report.write("---------------------------\n")
    report.write(f"Total Packets Analyzed: {len(packets)}\n\n")

    if alerts:
        report.write("Alerts Detected:\n")
        for a in alerts:
            report.write(a + "\n")
    else:
        report.write("No suspicious activity detected.\n")

print("Security report generated successfully.")