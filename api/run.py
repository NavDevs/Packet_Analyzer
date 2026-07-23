import base64
import io
import struct
import json
import sys
import os
import mimetypes
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from dpi_types import APP_NAMES, AppType, sni_to_app_type
from sni_extractor import SNIExtractor, HTTPHostExtractor
from packet_parser import PacketParser


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


# Root of the repo — two levels up from api/run.py
_REPO_ROOT = os.path.join(os.path.dirname(__file__), '..')
_PUBLIC_DIR = os.path.join(_REPO_ROOT, 'public')


def _serve_static(handler_instance, rel_path):
    """Serve a file from the public/ directory."""
    # Default to index.html for root or unknown paths
    if rel_path in ('/', ''):
        rel_path = '/index.html'

    file_path = os.path.join(_PUBLIC_DIR, rel_path.lstrip('/'))
    # Security: prevent directory traversal
    file_path = os.path.realpath(file_path)
    if not file_path.startswith(os.path.realpath(_PUBLIC_DIR)):
        _send_json(handler_instance, {'error': 'Forbidden'}, status=403)
        return

    if not os.path.isfile(file_path):
        # For SPA-style routing fall back to index.html
        file_path = os.path.join(_PUBLIC_DIR, 'index.html')

    mime_type, _ = mimetypes.guess_type(file_path)
    mime_type = mime_type or 'application/octet-stream'

    with open(file_path, 'rb') as f:
        content = f.read()

    handler_instance.send_response(200)
    handler_instance.send_header('Content-Type', mime_type)
    handler_instance.send_header('Content-Length', str(len(content)))
    handler_instance.end_headers()
    handler_instance.wfile.write(content)


def _send_json(handler_instance, data, status=200):
    """Helper to send a JSON response."""
    body = json.dumps(data).encode('utf-8')
    handler_instance.send_response(status)
    handler_instance.send_header('Content-Type', 'application/json')
    handler_instance.send_header('Content-Length', str(len(body)))
    handler_instance.send_header('Access-Control-Allow-Origin', '*')
    handler_instance.end_headers()
    handler_instance.wfile.write(body)


def _handle_get_apps(handler_instance):
    """Handle GET /api/apps — returns list of detectable apps."""
    apps = []
    skip = {'Unknown', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'QUIC'}
    for app_type, name in APP_NAMES.items():
        if name not in skip:
            apps.append({'id': name.lower(), 'name': name})
    _send_json(handler_instance, apps)


def _handle_post_run(handler_instance):
    """Handle POST /api/run — analyse uploaded pcap data."""
    content_length = int(handler_instance.headers.get('Content-Length', 0))
    raw_body = handler_instance.rfile.read(content_length)

    try:
        body = json.loads(raw_body.decode('utf-8'))
    except Exception:
        _send_json(handler_instance, {'success': False, 'error': 'Invalid JSON'}, status=400)
        return

    pcap_base64 = body.get('pcap_data', '')
    rules = body.get('rules', [])

    if not pcap_base64:
        _send_json(handler_instance, {'success': False, 'error': 'No pcap_data provided'}, status=400)
        return

    try:
        pcap_bytes = base64.b64decode(pcap_base64)
        reader = SimplePcapReader(pcap_bytes)
    except Exception as e:
        _send_json(handler_instance, {'success': False, 'error': f'Failed to decode pcap: {e}'}, status=400)
        return

    # Build rule sets
    blocked_apps = set()
    blocked_domains = []
    blocked_ips = set()

    for rule in rules:
        rule_type = rule.get('type', '')
        value = rule.get('value', '')
        if rule_type == 'app':
            for app_type, name in APP_NAMES.items():
                if name.lower() == value.lower():
                    blocked_apps.add(app_type)
                    break
        elif rule_type == 'domain':
            blocked_domains.append(value.lower())
        elif rule_type == 'ip':
            blocked_ips.add(value)

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
        parsed = PacketParser.parse_packet(bytes(pkt['data']))

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
        src_port = parsed['src_port']
        payload = parsed['payload']
        sni = ''
        app_type = AppType.UNKNOWN

        if dst_port == 443 and payload:
            sni = SNIExtractor.extract(bytes(payload)) or ''
            app_type = sni_to_app_type(sni) if sni else AppType.HTTPS
        elif dst_port == 80 and payload:
            host = HTTPHostExtractor.extract(bytes(payload))
            if host:
                sni = host
                app_type = sni_to_app_type(host)
            else:
                app_type = AppType.HTTP
        elif dst_port == 53 or src_port == 53:
            app_type = AppType.DNS
        else:
            app_type = AppType.UNKNOWN

        if sni and sni not in detected_snis:
            detected_snis[sni] = app_type

        app_counts[app_type] = app_counts.get(app_type, 0) + 1

        blocked = False
        if app_type in blocked_apps:
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
    for app_type, count in app_counts.items():
        pct = 100.0 * count / stats['total_packets'] if stats['total_packets'] > 0 else 0
        app_breakdown.append({
            'name': APP_NAMES.get(app_type, 'Unknown'),
            'count': count,
            'percentage': round(pct, 1)
        })
    app_breakdown.sort(key=lambda x: x['count'], reverse=True)

    detected_list = [
        {'domain': sni, 'app': APP_NAMES.get(app, 'Unknown')}
        for sni, app in detected_snis.items()
    ]

    _send_json(handler_instance, {
        'success': True,
        'stats': stats,
        'app_breakdown': app_breakdown,
        'detected_snis': detected_list
    })


class handler(BaseHTTPRequestHandler):
    """Vercel Python Serverless Function handler."""

    def log_message(self, format, *args):
        # Suppress default access log noise in Vercel logs
        pass

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/api/apps'):
            _handle_get_apps(self)
        elif self.path.startswith('/api/'):
            _send_json(self, {'error': 'Not found'}, status=404)
        else:
            # Serve static frontend files (index.html, favicon, etc.)
            _serve_static(self, self.path)

    def do_POST(self):
        if self.path.startswith('/api/run'):
            _handle_post_run(self)
        else:
            _send_json(self, {'error': 'Not found'}, status=404)
