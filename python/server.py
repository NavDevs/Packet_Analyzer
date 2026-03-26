from flask import Flask, request, jsonify, send_from_directory
import subprocess
import json
import os
import sys
import threading
import queue

app = Flask(__name__, static_folder='static')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), 'python')


class DPIRunner:
    def __init__(self):
        self.latest_result = None
        self.is_running = False
        self._lock = threading.Lock()
    
    def run(self, input_file, output_file, rules):
        with self._lock:
            self.is_running = True
        
        sys.path.insert(0, PYTHON_DIR)
        
        try:
            from dpi_engine import DPIEngine
            from dpi_types import APP_NAMES
            
            engine = DPIEngine(num_lbs=2, fps_per_lb=2)
            
            for rule in rules:
                rule_type = rule.get('type')
                value = rule.get('value')
                if rule_type == 'ip':
                    engine.block_ip(value)
                elif rule_type == 'app':
                    engine.block_app(value)
                elif rule_type == 'domain':
                    engine.block_domain(value)
            
            engine.process(input_file, output_file)
            
            result = {
                'success': True,
                'stats': {
                    'total_packets': engine.stats.total_packets,
                    'total_bytes': engine.stats.total_bytes,
                    'tcp_packets': engine.stats.tcp_packets,
                    'udp_packets': engine.stats.udp_packets,
                    'forwarded': engine.stats.forwarded,
                    'dropped': engine.stats.dropped
                },
                'app_breakdown': [],
                'detected_snis': []
            }
            
            for app_type, count in engine.stats.app_counts.items():
                pct = 100.0 * count / engine.stats.total_packets if engine.stats.total_packets > 0 else 0
                result['app_breakdown'].append({
                    'name': APP_NAMES.get(app_type, 'Unknown'),
                    'count': count,
                    'percentage': round(pct, 1)
                })
            
            result['app_breakdown'].sort(key=lambda x: x['count'], reverse=True)
            
            for sni, app in engine.stats.detected_snis.items():
                result['detected_snis'].append({
                    'domain': sni,
                    'app': APP_NAMES.get(app, 'Unknown')
                })
            
            with self._lock:
                self.latest_result = result
                self.is_running = False
            
            return result
            
        except Exception as e:
            with self._lock:
                self.is_running = False
            return {'success': False, 'error': str(e)}


dpi_runner = DPIRunner()


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)


@app.route('/api/run', methods=['POST'])
def run_analysis():
    data = request.json
    
    input_file = data.get('input_file', os.path.join(os.path.dirname(SCRIPT_DIR), 'test_dpi.pcap'))
    output_file = data.get('output_file', os.path.join(SCRIPT_DIR, 'output_demo.pcap'))
    rules = data.get('rules', [])
    
    result = dpi_runner.run(input_file, output_file, rules)
    return jsonify(result)


@app.route('/api/status')
def status():
    with dpi_runner._lock:
        return jsonify({
            'is_running': dpi_runner.is_running,
            'has_result': dpi_runner.latest_result is not None
        })


@app.route('/api/result')
def get_result():
    with dpi_runner._lock:
        if dpi_runner.latest_result:
            return jsonify(dpi_runner.latest_result)
        return jsonify({'success': False, 'error': 'No result available'})


@app.route('/api/pcap-files')
def list_pcap_files():
    files = []
    search_dirs = [
        os.path.dirname(SCRIPT_DIR),
        SCRIPT_DIR,
        os.path.join(SCRIPT_DIR, 'samples')
    ]
    
    for search_dir in search_dirs:
        if os.path.exists(search_dir):
            for f in os.listdir(search_dir):
                if f.endswith('.pcap'):
                    full_path = os.path.join(search_dir, f)
                    size = os.path.getsize(full_path)
                    files.append({
                        'name': f,
                        'path': full_path,
                        'size': size
                    })
    
    return jsonify(files)


@app.route('/api/apps')
def list_apps():
    sys.path.insert(0, PYTHON_DIR)
    from dpi_types import APP_NAMES
    
    apps = []
    skip_types = {'UNKNOWN', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'QUIC'}
    
    for app_type, name in APP_NAMES.items():
        if name not in skip_types:
            apps.append({'id': name.lower(), 'name': name})
    
    return jsonify(apps)


if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    print("Starting DPI Dashboard Server...")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5000)
