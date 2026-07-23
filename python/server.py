from flask import Flask, request, jsonify, send_from_directory
import os
import sys
import threading

# ── Absolute paths that work on Vercel serverless ────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='/static')


# ── DPI Runner with lazy import (avoids cold-start crashes) ──────────────────
class DPIRunner:
    def __init__(self):
        self.latest_result = None
        self.is_running = False
        self._engine = None
        self._lock = threading.Lock()

    def _get_engine(self):
        if self._engine is None:
            sys.path.insert(0, BASE_DIR)
            from dpi_engine import DPIEngine
            from dpi_types import APP_NAMES  # noqa: F401
            self._engine = DPIEngine(num_lbs=2, fps_per_lb=2)
        return self._engine

    def run(self, input_file, output_file, rules):
        with self._lock:
            self.is_running = True
        try:
            engine = self._get_engine()
            for rule in rules:
                rtype = rule.get('type')
                val = rule.get('value', '')
                if rtype == 'ip':
                    engine.block_ip(val)
                elif rtype == 'app':
                    engine.block_app(val)
                elif rtype == 'domain':
                    engine.block_domain(val)

            engine.process(input_file, output_file)

            from dpi_types import APP_NAMES
            result = {
                'success': True,
                'stats': {
                    'total_packets': engine.stats.total_packets,
                    'total_bytes': engine.stats.total_bytes,
                    'tcp_packets': engine.stats.tcp_packets,
                    'udp_packets': engine.stats.udp_packets,
                    'forwarded': engine.stats.forwarded,
                    'dropped': engine.stats.dropped,
                },
                'app_breakdown': sorted([
                    {
                        'name': APP_NAMES.get(t, 'Unknown'),
                        'count': c,
                        'percentage': round(100.0 * c / engine.stats.total_packets, 1)
                        if engine.stats.total_packets > 0 else 0,
                    }
                    for t, c in engine.stats.app_counts.items()
                ], key=lambda x: x['count'], reverse=True),
                'detected_snis': [
                    {'domain': sni, 'app': APP_NAMES.get(a, 'Unknown')}
                    for sni, a in engine.stats.detected_snis.items()
                ],
            }

            with self._lock:
                self.latest_result = result
                self.is_running = False
            return result

        except Exception as e:
            import traceback
            traceback.print_exc()
            with self._lock:
                self.is_running = False
            return {'success': False, 'error': str(e)}


dpi_runner = DPIRunner()


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'index.html')


@app.route('/api/run', methods=['POST'])
def run_analysis():
    data = request.get_json(silent=True) or {}
    default_pcap = os.path.join(os.path.dirname(BASE_DIR), 'test_dpi.pcap')
    input_file = data.get('input_file', default_pcap)
    output_file = os.path.join(BASE_DIR, 'output_demo.pcap')
    rules = data.get('rules', [])
    return jsonify(dpi_runner.run(input_file, output_file, rules))


@app.route('/api/status')
def api_status():
    with dpi_runner._lock:
        return jsonify({
            'is_running': dpi_runner.is_running,
            'has_result': dpi_runner.latest_result is not None,
        })


@app.route('/api/result')
def api_result():
    with dpi_runner._lock:
        if dpi_runner.latest_result:
            return jsonify(dpi_runner.latest_result)
        return jsonify({'success': False, 'error': 'No result available'})


@app.route('/api/pcap-files')
def api_pcap_files():
    files = []
    for d in [os.path.dirname(BASE_DIR), BASE_DIR]:
        if os.path.exists(d):
            for f in os.listdir(d):
                if f.endswith('.pcap'):
                    try:
                        files.append({
                            'name': f,
                            'path': os.path.join(d, f),
                            'size': os.path.getsize(os.path.join(d, f)),
                        })
                    except OSError:
                        pass
    return jsonify(files)


@app.route('/api/apps')
def api_apps():
    from dpi_types import APP_NAMES
    skip = {'UNKNOWN', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'QUIC'}
    apps = [
        {'id': name.lower(), 'name': name}
        for _, name in sorted(APP_NAMES.items())
        if name not in skip
    ]
    return jsonify(apps)


# ── Vercel WSGI entry: expose `app` directly ────────────────────────────────
# Vercel's Python runtime auto-detects a top-level `app` (WSGI) or
# `application` (Django WSGI) variable — no handler wrapper needed.
if __name__ == '__main__':
    os.makedirs(STATIC_DIR, exist_ok=True)
    print(f"Static files served from: {STATIC_DIR}")
    app.run(debug=True, host='0.0.0.0', port=5000)
