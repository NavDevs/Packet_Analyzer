import base64
import io
import struct
import json
import sys
import os

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


def handler(req, res):
    if req.method == 'GET':
        if req.path == '/api/apps':
            apps = []
            skip = {'UNKNOWN', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'QUIC'}
            for app_type, name in APP_NAMES.items():
                if name not in skip:
                    apps.append({'id': name.lower(), 'name': name})
            return res.json(apps)
        
        return res.json({'error': 'Not found'}, status=404)
    
    if req.method == 'POST' and req.path == '/api/run':
        try:
            body = req.json()
        except:
            return res.json({'success': False, 'error': 'Invalid JSON'}, status=400)
        
        pcap_base64 = body.get('pcap_data', '')
        rules = body.get('rules', [])
        
        if pcap_base64:
            pcap_bytes = base64.b64decode(pcap_base64)
            reader = SimplePcapReader(pcap_bytes)
        else:
            return res.json({'success': False, 'error': 'No pcap_data provided'}, status=400)
        
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
                if sni:
                    app_type = sni_to_app_type(sni)
                else:
                    app_type = AppType.HTTPS
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
        
        detected_list = []
        for sni, app in detected_snis.items():
            detected_list.append({
                'domain': sni,
                'app': APP_NAMES.get(app, 'Unknown')
            })
        
        return res.json({
            'success': True,
            'stats': stats,
            'app_breakdown': app_breakdown,
            'detected_snis': detected_list
        })
    
    return res.json({'error': 'Not found'}, status=404)
