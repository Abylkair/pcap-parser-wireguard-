from flask import Flask, render_template, request, jsonify
from scapy.all import rdpcap, Ether, IP, TCP, Dot11, Dot3, ARP
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
    # Логика для обнаружения подозрительных пакетов
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
    # Логика для обнаружения атаки воспроизведения
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
    # Логика для обнаружения поддельных точек доступа
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
                        'type': 'IPv4' if packet[Ether].type == 0x0800 else 'Unknown' if packet.haslayer(Ether) else ''
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
                'Evil Twin Attackers': evil_twin_attackers
            }

            return jsonify({'packets': packet_data, 'attacks': attack_summary})
        except Exception as e:
            logger.error(f"Error parsing PCAP file: {e}")
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Invalid file format'}), 400

if __name__ == '__main__':
    app.run(debug=True)
