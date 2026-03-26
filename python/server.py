from flask import Flask, request, jsonify, send_from_directory
import os
import sys
import base64
import tempfile
import struct

app = Flask(__name__, static_folder='static')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = SCRIPT_DIR


class SimplePcapReader:
    def __init__(self, data):
        self.data = data
        self.offset = 24
        self.packets = []
        self._read_all()
    
    def _read_all(self):
        while self.offset + 16 <= len(self.data):
            ts_sec = struct.unpack('<I', self.data[self.offset:self.offset+4])[0]
            ts_usec = struct.unpack('<I', self.data[self.offset+4:self.offset+8])[0]
            incl_len = struct.unpack('<I', self.data[self.offset+8:self.offset+12])[0]
            self.offset += 16
            
            if self.offset + incl_len > len(self.data):
                break
            
            pkt_data = self.data[self.offset:self.offset+incl_len]
            self.packets.append({
                'ts_sec': ts_sec,
                'ts_usec': ts_usec,
                'data': pkt_data
            })
            self.offset += incl_len


def parse_ip_header(data, offset):
    if len(data) < offset + 20:
        return None
    
    version = (data[offset] >> 4) & 0xF
    if version != 4:
        return None
    
    ihl = data[offset] & 0xF
    header_len = ihl * 4
    
    if len(data) < offset + header_len:
        return None
    
    protocol = data[offset + 9]
    src_ip = f"{data[offset+12]}.{data[offset+13]}.{data[offset+14]}.{data[offset+15]}"
    dst_ip = f"{data[offset+16]}.{data[offset+17]}.{data[offset+18]}.{data[offset+19]}"
    
    return {
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'next_offset': offset + header_len
    }


def parse_tcp_header(data, offset):
    if len(data) < offset + 20:
        return None
    
    src_port = struct.unpack('!H', data[offset:offset+2])[0]
    dst_port = struct.unpack('!H', data[offset+2:offset+4])[0]
    flags = data[offset+13]
    
    data_offset = (data[offset+12] >> 4) & 0xF
    header_len = data_offset * 4
    
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'flags': flags,
        'next_offset': offset + header_len
    }


def parse_udp_header(data, offset):
    if len(data) < offset + 8:
        return None
    
    src_port = struct.unpack('!H', data[offset:offset+2])[0]
    dst_port = struct.unpack('!H', data[offset+2:offset+4])[0]
    
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'next_offset': offset + 8
    }


def parse_packet(data):
    result = {
        'valid': False,
        'src_ip': None,
        'dst_ip': None,
        'protocol': None,
        'src_port': 0,
        'dst_port': 0,
        'payload': b'',
        'tcp_flags': 0
    }
    
    if len(data) < 34:
        return result
    
    ether_type = struct.unpack('!H', data[12:14])[0]
    if ether_type != 0x0800:
        return result
    
    ip = parse_ip_header(data, 14)
    if not ip:
        return result
    
    result['src_ip'] = ip['src_ip']
    result['dst_ip'] = ip['dst_ip']
    result['protocol'] = ip['protocol']
    
    if ip['protocol'] == 6:
        tcp = parse_tcp_header(data, ip['next_offset'])
        if tcp:
            result['src_port'] = tcp['src_port']
            result['dst_port'] = tcp['dst_port']
            result['tcp_flags'] = tcp['flags']
            result['payload'] = data[tcp['next_offset']:]
    elif ip['protocol'] == 17:
        udp = parse_udp_header(data, ip['next_offset'])
        if udp:
            result['src_port'] = udp['src_port']
            result['dst_port'] = udp['dst_port']
            result['payload'] = data[udp['next_offset']:]
    
    result['valid'] = True
    return result


def read_uint16_be(data, offset):
    return (data[offset] << 8) | data[offset + 1]


def extract_sni(payload):
    if len(payload) < 9:
        return None
    
    if payload[0] != 0x16:
        return None
    
    version = read_uint16_be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return None
    
    if payload[5] != 0x01:
        return None
    
    try:
        offset = 9
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        
        cipher_suites_len = read_uint16_be(payload, offset)
        offset += 2 + cipher_suites_len
        
        compression_len = payload[offset]
        offset += 1 + compression_len
        
        extensions_len = read_uint16_be(payload, offset)
        offset += 2
        
        ext_end = offset + extensions_len
        if ext_end > len(payload):
            ext_end = len(payload)
        
        while offset + 4 <= ext_end:
            ext_type = read_uint16_be(payload, offset)
            ext_len = read_uint16_be(payload, offset + 2)
            offset += 4
            
            if offset + ext_len > ext_end:
                break
            
            if ext_type == 0x0000:
                if ext_len < 5:
                    break
                
                sni_list_len = read_uint16_be(payload, offset)
                if sni_list_len < 3:
                    break
                
                sni_type = payload[offset + 2]
                sni_len = read_uint16_be(payload, offset + 3)
                
                if sni_type != 0x00:
                    break
                
                sni = payload[offset + 5:offset + 5 + sni_len].decode('utf-8', errors='ignore')
                return sni
            
            offset += ext_len
    except:
        pass
    
    return None


def extract_http_host(payload):
    try:
        text = payload.decode('utf-8', errors='ignore')
        for line in text.split('\n'):
            if line.lower().startswith('host:'):
                host = line[5:].strip()
                if ':' in host:
                    host = host[:host.index(':')]
                return host.strip()
    except:
        pass
    return None


APP_NAMES = {
    'YOUTUBE': 'YouTube',
    'FACEBOOK': 'Facebook',
    'GOOGLE': 'Google',
    'INSTAGRAM': 'Instagram',
    'TWITTER': 'Twitter/X',
    'NETFLIX': 'Netflix',
    'AMAZON': 'Amazon',
    'MICROSOFT': 'Microsoft',
    'APPLE': 'Apple',
    'WHATSAPP': 'WhatsApp',
    'TELEGRAM': 'Telegram',
    'TIKTOK': 'TikTok',
    'SPOTIFY': 'Spotify',
    'ZOOM': 'Zoom',
    'DISCORD': 'Discord',
    'GITHUB': 'GitHub',
    'CLOUDFLARE': 'Cloudflare',
}


def sni_to_app(sni):
    if not sni:
        return 'Unknown'
    
    lower = sni.lower()
    
    if any(x in lower for x in ['youtube', 'ytimg', 'youtu.be']):
        return 'YouTube'
    if any(x in lower for x in ['google', 'gstatic', 'googleapis']):
        return 'Google'
    if any(x in lower for x in ['facebook', 'fbcdn', 'meta.com']):
        return 'Facebook'
    if any(x in lower for x in ['instagram', 'cdninstagram']):
        return 'Instagram'
    if any(x in lower for x in ['twitter', 'twimg', 'x.com']):
        return 'Twitter/X'
    if any(x in lower for x in ['netflix', 'nflxvideo']):
        return 'Netflix'
    if any(x in lower for x in ['amazon', 'aws', 'cloudfront']):
        return 'Amazon'
    if any(x in lower for x in ['microsoft', 'office', 'azure', 'bing']):
        return 'Microsoft'
    if any(x in lower for x in ['apple', 'icloud', 'mzstatic']):
        return 'Apple'
    if any(x in lower for x in ['spotify', 'scdn.co']):
        return 'Spotify'
    if any(x in lower for x in ['discord', 'discordapp']):
        return 'Discord'
    if any(x in lower for x in ['tiktok', 'tiktokcdn']):
        return 'TikTok'
    if any(x in lower for x in ['github', 'githubusercontent']):
        return 'GitHub'
    
    return 'HTTPS'


def analyze_pcap(pcap_data, rules):
    sys.path.insert(0, PYTHON_DIR)
    
    pcap_bytes = base64.b64decode(pcap_data)
    reader = SimplePcapReader(pcap_bytes)
    
    blocked_apps = set()
    blocked_domains = []
    
    for rule in rules:
        rule_type = rule.get('type', '')
        value = rule.get('value', '').lower()
        if rule_type == 'app':
            blocked_apps.add(value.title())
        elif rule_type == 'domain':
            blocked_domains.append(value)
    
    stats = {
        'total_packets': 0,
        'total_bytes': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'forwarded': 0,
        'dropped': 0
    }
    
    app_counts = {}
    detected_snis = {}
    
    for pkt in reader.packets:
        parsed = parse_packet(bytes(pkt['data']))
        
        if not parsed['valid']:
            continue
        
        if parsed['protocol'] not in (6, 17):
            continue
        
        stats['total_packets'] += 1
        stats['total_bytes'] += len(pkt['data'])
        
        if parsed['protocol'] == 6:
            stats['tcp_packets'] += 1
        else:
            stats['udp_packets'] += 1
        
        dst_port = parsed['dst_port']
        payload = parsed['payload']
        sni = ''
        app_name = 'Unknown'
        
        if dst_port == 443 and payload:
            sni = extract_sni(bytes(payload)) or ''
            if sni:
                app_name = sni_to_app(sni)
            else:
                app_name = 'HTTPS'
        elif dst_port == 80 and payload:
            host = extract_http_host(bytes(payload))
            if host:
                sni = host
                app_name = sni_to_app(host)
            else:
                app_name = 'HTTP'
        elif dst_port == 53 or parsed['src_port'] == 53:
            app_name = 'DNS'
        
        if sni and sni not in detected_snis:
            detected_snis[sni] = app_name
        
        app_counts[app_name] = app_counts.get(app_name, 0) + 1
        
        blocked = False
        if app_name in blocked_apps:
            blocked = True
        elif sni:
            sni_lower = sni.lower()
            for dom in blocked_domains:
                if dom in sni_lower:
                    blocked = True
                    break
        
        if blocked:
            stats['dropped'] += 1
        else:
            stats['forwarded'] += 1
    
    app_breakdown = []
    for app_name, count in app_counts.items():
        pct = 100.0 * count / stats['total_packets'] if stats['total_packets'] > 0 else 0
        app_breakdown.append({
            'name': app_name,
            'count': count,
            'percentage': round(pct, 1)
        })
    
    app_breakdown.sort(key=lambda x: x['count'], reverse=True)
    
    detected_list = []
    for sni, app in detected_snis.items():
        detected_list.append({
            'domain': sni,
            'app': app
        })
    
    return {
        'success': True,
        'stats': stats,
        'app_breakdown': app_breakdown,
        'detected_snis': detected_list
    }


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)


@app.route('/api/run', methods=['POST'])
def run_analysis():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        pcap_data = data.get('pcap_data', '')
        rules = data.get('rules', [])
        
        if not pcap_data:
            return jsonify({'success': False, 'error': 'No PCAP file provided'}), 400
        
        result = analyze_pcap(pcap_data, rules)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/apps', methods=['GET'])
def list_apps():
    apps = [
        {'id': 'youtube', 'name': 'YouTube'},
        {'id': 'facebook', 'name': 'Facebook'},
        {'id': 'google', 'name': 'Google'},
        {'id': 'instagram', 'name': 'Instagram'},
        {'id': 'netflix', 'name': 'Netflix'},
        {'id': 'tiktok', 'name': 'TikTok'},
        {'id': 'twitter', 'name': 'Twitter/X'},
        {'id': 'discord', 'name': 'Discord'},
        {'id': 'spotify', 'name': 'Spotify'},
    ]
    return jsonify(apps)


if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    print("Starting DPI Dashboard Server...")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5000)
