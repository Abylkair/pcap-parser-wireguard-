from flask import Flask, render_template, request, jsonify
from scapy.all import rdpcap, Ether, IP, TCP, Dot11, Dot3, ARP, DNS, ICMP
import logging

app = Flask(__name__)

# Настройка логгера для Flask
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Настройка обработчика для вывода в консоль
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

def get_network_type(packet):
    if packet.haslayer(Ether):
        return 'Ethernet'
    elif packet.haslayer(Dot11):
        return 'WiFi'
    elif packet.haslayer(Dot3):
        return 'Token Ring'
    else:
        return 'Unknown'

def detect_deauth_attack(packets):
    deauth_packets = []
    attackers = set()
    for packet in packets:
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:
            deauth_packets.append(packet)
            attackers.add(packet.addr2)  # MAC address of the attacker
    return len(deauth_packets) > 0, deauth_packets, list(attackers)

def detect_arp_spoofing(packets):
    arp_packets = []
    ip_mac_map = {}
    spoofing_detected = False
    spoofing_details = []
    attackers = set()

    for packet in packets:
        if packet.haslayer(ARP):
            arp_packets.append(packet)
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            if src_ip in ip_mac_map:
                if ip_mac_map[src_ip] != src_mac:
                    spoofing_detected = True
                    spoofing_details.append(packet)
                    attackers.add(src_mac)  # MAC address of the attacker
            else:
                ip_mac_map[src_ip] = src_mac
    return spoofing_detected, spoofing_details, list(attackers)

def detect_packet_sniffing(packets):
    sniffing_detected = False
    sniffing_packets = []
    attackers = set()

    for packet in packets:
        if packet.haslayer(IP) and packet[IP].dst == '255.255.255.255':  # Broadcast address
            sniffing_detected = True
            sniffing_packets.append(packet)
            attackers.add(packet[IP].src)
    
    return sniffing_detected, sniffing_packets, list(attackers)

def detect_replay_attack(packets):
    replay_detected = False
    replay_packets = []
    seen_packets = set()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            packet_id = (packet[IP].src, packet[IP].dst, packet[TCP].seq, packet[TCP].ack)
            if packet_id in seen_packets:
                replay_detected = True
                replay_packets.append(packet)
            else:
                seen_packets.add(packet_id)
    
    return replay_detected, replay_packets, []

def detect_evil_twin(packets):
    evil_twin_detected = False
    evil_twin_packets = []
    attackers = set()

    ssid_map = {}

    for packet in packets:
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                ssid = packet.info.decode()
                bssid = packet.addr2
                if ssid in ssid_map:
                    if ssid_map[ssid] != bssid:
                        evil_twin_detected = True
                        evil_twin_packets.append(packet)
                        attackers.add(bssid)
                else:
                    ssid_map[ssid] = bssid
    
    return evil_twin_detected, evil_twin_packets, list(attackers)

def detect_dns_tunneling(packets):
    dns_tunneling_detected = False
    tunneling_packets = []
    attackers = set()

    for packet in packets:
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS request
            if len(packet[DNS].qd.qname) > 50:  # Suspiciously long domain name
                dns_tunneling_detected = True
                tunneling_packets.append(packet)
                attackers.add(packet[IP].src)
    
    return dns_tunneling_detected, tunneling_packets, list(attackers)

def detect_icmp_flood(packets):
    icmp_flood_detected = False
    icmp_packets = []
    attackers = set()
    icmp_count = {}

    for packet in packets:
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src
            if src_ip in icmp_count:
                icmp_count[src_ip] += 1
            else:
                icmp_count[src_ip] = 1
            
            if icmp_count[src_ip] > 100:  # Threshold for flood detection
                icmp_flood_detected = True
                icmp_packets.append(packet)
                attackers.add(src_ip)
    
    return icmp_flood_detected, icmp_packets, list(attackers)

def detect_port_scanning(packets):
    port_scanning_detected = False
    scanning_packets = []
    attackers = set()
    port_count = {}

    for packet in packets:
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            if src_ip in port_count:
                if dst_port in port_count[src_ip]:
                    port_count[src_ip][dst_port] += 1
                else:
                    port_count[src_ip][dst_port] = 1
            else:
                port_count[src_ip] = {dst_port: 1}

            if len(port_count[src_ip]) > 10:  # Threshold for port scan detection
                port_scanning_detected = True
                scanning_packets.append(packet)
                attackers.add(src_ip)
    
    return port_scanning_detected, scanning_packets, list(attackers)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/parse', methods=['POST'])
def parse_pcap():
    pcap_file = request.files['file']
    if pcap_file and pcap_file.filename.endswith('.pcap'):
        try:
            packets = rdpcap(pcap_file)
            packet_data = []

            for packet in packets:
                network_type = get_network_type(packet)
                packet_info = {
                    'Network Type': network_type,
                    'Ethernet': {
                        'dst': packet[Ether].dst if packet.haslayer(Ether) else '',
                        'src': packet[Ether].src if packet.haslayer(Ether) else '',
                        'type': 'IPv4' if packet.haslayer(Ether) and packet[Ether].type == 0x0800 else 'Unknown'
                    }
                }
                if packet.haslayer(IP):
                    ip_layer = packet.getlayer(IP)
                    packet_info['IP'] = {
                        'version': ip_layer.version,
                        'ihl': ip_layer.ihl,
                        'tos': ip_layer.tos,
                        'len': ip_layer.len,
                        'id': ip_layer.id,
                        'flags': str(ip_layer.flags),
                        'frag': ip_layer.frag,
                        'ttl': ip_layer.ttl,
                        'proto': 'TCP' if ip_layer.proto == 6 else 'Other',
                        'chksum': ip_layer.chksum,
                        'src': ip_layer.src,
                        'dst': ip_layer.dst
                    }
                    if packet.haslayer(TCP):
                        tcp_layer = packet.getlayer(TCP)
                        packet_info['TCP'] = {
                            'sport': tcp_layer.sport,
                            'dport': tcp_layer.dport,
                            'seq': tcp_layer.seq,
                            'ack': tcp_layer.ack,
                            'dataofs': tcp_layer.dataofs,
                            'reserved': tcp_layer.reserved,
                            'flags': str(tcp_layer.flags),
                            'window': tcp_layer.window,
                            'chksum': tcp_layer.chksum,
                            'urgptr': tcp_layer.urgptr,
                            'options': [(opt[0], str(opt[1]) if isinstance(opt[1], bytes) else opt[1]) for opt in tcp_layer.options]
                        }

                packet_data.append(packet_info)

            deauth_detected, deauth_packets, deauth_attackers = detect_deauth_attack(packets)
            arp_spoofing_detected, arp_spoofing_packets, arp_attackers = detect_arp_spoofing(packets)
            sniffing_detected, sniffing_packets, sniffing_attackers = detect_packet_sniffing(packets)
            replay_detected, replay_packets, replay_attackers = detect_replay_attack(packets)
            evil_twin_detected, evil_twin_packets, evil_twin_attackers = detect_evil_twin(packets)
            dns_tunneling_detected, dns_tunneling_packets, dns_attackers = detect_dns_tunneling(packets)
            icmp_flood_detected, icmp_flood_packets, icmp_attackers = detect_icmp_flood(packets)
            port_scanning_detected, port_scanning_packets, port_attackers = detect_port_scanning(packets)

            attack_summary = {
                'Deauthentication Attack': deauth_detected,
                'Deauth Attackers': deauth_attackers,
                'ARP Spoofing': arp_spoofing_detected,
                'ARP Attackers': arp_attackers,
                'Packet Sniffing': sniffing_detected,
                'Sniffing Attackers': sniffing_attackers,
                'Replay Attack': replay_detected,
                'Replay Attackers': replay_attackers,
                'Evil Twin': evil_twin_detected,
                'Evil Twin Attackers': evil_twin_attackers,
                'DNS Tunneling': dns_tunneling_detected,
                'DNS Attackers': dns_attackers,
                'ICMP Flood': icmp_flood_detected,
                'ICMP Attackers': icmp_attackers,
                'Port Scanning': port_scanning_detected,
                'Port Attackers': port_attackers
            }

            return jsonify({'packets': packet_data, 'attacks': attack_summary})
        except Exception as e:
            logger.error(f"Error parsing PCAP file: {e}")
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Invalid file format'}), 400

if __name__ == '__main__':
    app.run(debug=True)
