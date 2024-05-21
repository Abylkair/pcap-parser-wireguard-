from flask import Flask, render_template, request, jsonify
from scapy.all import rdpcap, Ether, IP, TCP, Dot11, Dot3
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
    # Добавьте другие типы сетевых подключений по мере необходимости
    else:
        return 'Unknown'

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
                        'dst': packet[Ether].dst,
                        'src': packet[Ether].src,
                        'type': 'IPv4' if packet[Ether].type == 0x0800 else 'Unknown'
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

            return jsonify({'packets': packet_data})
        except Exception as e:
            logger.error(f"Error parsing PCAP file: {e}")
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Invalid file format'}), 400

if __name__ == '__main__':
    app.run(debug=True)
