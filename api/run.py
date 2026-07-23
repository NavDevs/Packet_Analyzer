import base64
import struct
import json
import sys
import os
import mimetypes
from http.server import BaseHTTPRequestHandler

# Set up paths for importing python/ modules
_THIS_FILE = os.path.abspath(__file__)
_API_DIR   = os.path.dirname(_THIS_FILE)
_REPO_ROOT = os.path.dirname(_API_DIR)
_PYTHON_DIR = os.path.join(_REPO_ROOT, 'python')
_PUBLIC_DIR = os.path.join(_PYTHON_DIR, 'static')

if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)

from dpi_types import APP_NAMES, AppType, sni_to_app_type
from sni_extractor import SNIExtractor, HTTPHostExtractor
from packet_parser import PacketParser


def _serve_static(h, path):
    """Read a file from _PUBLIC_DIR (python/static) and write it to the response."""
    # Strip query string
    path = path.split('?')[0]

    if path in ('/', ''):
        path = '/index.html'

    # Resolve to absolute path and prevent directory traversal
    target = os.path.realpath(os.path.join(_PUBLIC_DIR, path.lstrip('/')))
    pub_real = os.path.realpath(_PUBLIC_DIR)

    if not target.startswith(pub_real):
        _send_json(h, {'error': 'Forbidden'}, status=403)
        return

    if not os.path.isfile(target):
        # SPA fallback — serve index.html
        target = os.path.join(_PUBLIC_DIR, 'index.html')

    if not os.path.isfile(target):
        _send_json(h, {'error': 'index.html not found', 'looked_in': _PUBLIC_DIR}, status=404)
        return

    mime, _ = mimetypes.guess_type(target)
    mime = mime or 'application/octet-stream'

    with open(target, 'rb') as f:
        body = f.read()

    h.send_response(200)
    h.send_header('Content-Type', mime)
    h.send_header('Content-Length', str(len(body)))
    h.end_headers()
    h.wfile.write(body)


class SimplePcapReader:
    def __init__(self, data):
        self.data = data
        self.offset = 24
        self.packets = []
        self._read_all()

    def _read_all(self):
        while self.offset + 16 <= len(self.data):
            ts_sec  = struct.unpack('<I', self.data[self.offset:self.offset+4])[0]
            ts_usec = struct.unpack('<I', self.data[self.offset+4:self.offset+8])[0]
            incl_len = struct.unpack('<I', self.data[self.offset+8:self.offset+12])[0]
            self.offset += 16
            if self.offset + incl_len > len(self.data):
                break
            pkt_data = self.data[self.offset:self.offset + incl_len]
            self.packets.append({'ts_sec': ts_sec, 'ts_usec': ts_usec, 'data': pkt_data})
            self.offset += incl_len


def _send_json(h, data, status=200):
    body = json.dumps(data).encode('utf-8')
    h.send_response(status)
    h.send_header('Content-Type', 'application/json')
    h.send_header('Content-Length', str(len(body)))
    h.send_header('Access-Control-Allow-Origin', '*')
    h.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    h.send_header('Access-Control-Allow-Headers', 'Content-Type')
    h.end_headers()
    h.wfile.write(body)


def _handle_get_apps(h):
    skip = {'Unknown', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'QUIC'}
    apps = [
        {'id': name.lower(), 'name': name}
        for app_type, name in APP_NAMES.items()
        if name not in skip
    ]
    _send_json(h, apps)


def _handle_post_run(h):
    content_length = int(h.headers.get('Content-Length', 0))
    raw = h.rfile.read(content_length)

    try:
        body = json.loads(raw.decode('utf-8'))
    except Exception:
        _send_json(h, {'success': False, 'error': 'Invalid JSON'}, status=400)
        return

    pcap_b64 = body.get('pcap_data', '')
    rules    = body.get('rules', [])

    if not pcap_b64:
        _send_json(h, {'success': False, 'error': 'No pcap_data provided'}, status=400)
        return

    try:
        pcap_bytes = base64.b64decode(pcap_b64)
        reader = SimplePcapReader(pcap_bytes)
    except Exception as e:
        _send_json(h, {'success': False, 'error': f'Bad pcap: {e}'}, status=400)
        return

    blocked_apps    = set()
    blocked_domains = []
    blocked_ips     = set()

    for rule in rules:
        rt, val = rule.get('type', ''), rule.get('value', '')
        if rt == 'app':
            for at, name in APP_NAMES.items():
                if name.lower() == val.lower():
                    blocked_apps.add(at)
                    break
        elif rt == 'domain':
            blocked_domains.append(val.lower())
        elif rt == 'ip':
            blocked_ips.add(val)

    stats = {'total_packets': 0, 'total_bytes': 0,
             'tcp_packets': 0, 'udp_packets': 0,
             'forwarded': 0, 'dropped': 0}
    app_counts   = {}
    detected_snis = {}

    for pkt in reader.packets:
        parsed = PacketParser.parse_packet(bytes(pkt['data']))
        if not parsed['valid'] or parsed['protocol'] not in (6, 17):
            continue

        stats['total_packets'] += 1
        stats['total_bytes']   += len(pkt['data'])

        if parsed['protocol'] == 6:
            stats['tcp_packets'] += 1
        else:
            stats['udp_packets'] += 1

        dst_port = parsed['dst_port']
        src_port = parsed['src_port']
        payload  = parsed['payload']
        sni      = ''
        app_type = AppType.UNKNOWN

        if dst_port == 443 and payload:
            sni = SNIExtractor.extract(bytes(payload)) or ''
            app_type = sni_to_app_type(sni) if sni else AppType.HTTPS
        elif dst_port == 80 and payload:
            host = HTTPHostExtractor.extract(bytes(payload))
            if host:
                sni, app_type = host, sni_to_app_type(host)
            else:
                app_type = AppType.HTTP
        elif dst_port == 53 or src_port == 53:
            app_type = AppType.DNS

        if sni and sni not in detected_snis:
            detected_snis[sni] = app_type

        app_counts[app_type] = app_counts.get(app_type, 0) + 1

        blocked = app_type in blocked_apps or (
            sni and any(d in sni.lower() for d in blocked_domains)
        )
        if blocked:
            stats['dropped'] += 1
        else:
            stats['forwarded'] += 1

    total = stats['total_packets'] or 1
    app_breakdown = sorted([
        {'name': APP_NAMES.get(at, 'Unknown'), 'count': c,
         'percentage': round(100.0 * c / total, 1)}
        for at, c in app_counts.items()
    ], key=lambda x: x['count'], reverse=True)

    detected_list = [
        {'domain': sni, 'app': APP_NAMES.get(app, 'Unknown')}
        for sni, app in detected_snis.items()
    ]

    _send_json(h, {
        'success': True,
        'stats': stats,
        'app_breakdown': app_breakdown,
        'detected_snis': detected_list
    })


class handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence access logs

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        normalized_path = self.path.split('?')[0].rstrip('/')
        if normalized_path == '/api/apps':
            _handle_get_apps(self)
        elif normalized_path == '/api/debug':
            def _ls(p):
                try:
                    return os.listdir(p)
                except Exception as ex:
                    return str(ex)
            _send_json(self, {
                '__file__': _THIS_FILE,
                'cwd': os.getcwd(),
                'repo_root': _REPO_ROOT,
                'public_dir': _PUBLIC_DIR,
                'public_exists': os.path.exists(_PUBLIC_DIR),
                'public_contents': _ls(_PUBLIC_DIR),
                'repo_root_contents': _ls(_REPO_ROOT),
                'api_dir_contents': _ls(_API_DIR),
            })
        elif normalized_path.startswith('/api'):
            _send_json(self, {'error': 'Not found'}, status=404)
        else:
            _serve_static(self, self.path)

    def do_POST(self):
        normalized_path = self.path.split('?')[0].rstrip('/')
        if normalized_path == '/api/run':
            _handle_post_run(self)
        else:
            _send_json(self, {'error': 'Not found'}, status=404)
