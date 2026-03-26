import threading
import queue
from typing import Dict, List, Optional, Set
from dpi_types import FiveTuple, Flow, Packet, Stats, AppType, sni_to_app_type
from sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor
from pcap_io import PcapReader, PcapWriter, PcapPacket
from packet_parser import PacketParser


class BlockingRules:
    def __init__(self):
        self.blocked_ips: Set[int] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: List[str] = []
        self._lock = threading.Lock()
    
    def block_ip(self, ip: str):
        addr = self._parse_ip(ip)
        with self._lock:
            self.blocked_ips.add(addr)
        print(f"[Rules] Blocked IP: {ip}")
    
    def block_app(self, app_name: str):
        from dpi_types import APP_NAMES
        with self._lock:
            for app_type, name in APP_NAMES.items():
                if name.lower() == app_name.lower():
                    self.blocked_apps.add(app_type)
                    print(f"[Rules] Blocked app: {name}")
                    return
        print(f"[Rules] Unknown app: {app_name}")
    
    def block_domain(self, domain: str):
        with self._lock:
            self.blocked_domains.append(domain.lower())
        print(f"[Rules] Blocked domain: {domain}")
    
    def is_blocked(self, src_ip: int, app_type: AppType, sni: str) -> bool:
        with self._lock:
            if src_ip in self.blocked_ips:
                return True
            if app_type in self.blocked_apps:
                return True
            sni_lower = sni.lower()
            for dom in self.blocked_domains:
                if dom in sni_lower:
                    return True
        return False
    
    @staticmethod
    def _parse_ip(ip: str) -> int:
        parts = ip.split('.')
        result = 0
        for i, part in enumerate(parts):
            result |= int(part) << (24 - i * 8)
        return result
    
    @staticmethod
    def ip_to_int(ip: str) -> int:
        return BlockingRules._parse_ip(ip)


class FastPath:
    def __init__(self, id: int, rules: BlockingRules, stats: Stats, output_queue: queue.Queue):
        self.id = id
        self.rules = rules
        self.stats = stats
        self.output_queue = output_queue
        self.flows: Dict[FiveTuple, Flow] = {}
        self.processed = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._input_queue: queue.Queue = queue.Queue(maxsize=10000)
    
    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
    
    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
    
    def get_queue(self) -> queue.Queue:
        return self._input_queue
    
    def get_processed(self) -> int:
        return self.processed
    
    def _run(self):
        while self._running:
            try:
                pkt = self._input_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            
            self.processed += 1
            
            flow = self.flows.get(pkt.tuple)
            if flow is None:
                flow = Flow(tuple=pkt.tuple)
                self.flows[pkt.tuple] = flow
            
            flow.packets += 1
            flow.bytes_count += len(pkt.raw_data)
            
            if not flow.classified:
                self._classify_flow(pkt, flow)
            
            if not flow.blocked:
                flow.blocked = self.rules.is_blocked(
                    BlockingRules.ip_to_int(pkt.tuple.src_ip),
                    flow.app_type,
                    flow.sni
                )
            
            self.stats.record_app(flow.app_type, flow.sni)
            
            if flow.blocked:
                self.stats.dropped += 1
            else:
                self.stats.forwarded += 1
                try:
                    self.output_queue.put_nowait(pkt)
                except queue.Full:
                    pass
    
    def _classify_flow(self, pkt: Packet, flow: Flow):
        if pkt.tuple.dst_port == 443 and pkt.payload:
            sni = SNIExtractor.extract(bytes(pkt.payload))
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return
        
        if pkt.tuple.dst_port == 80 and pkt.payload:
            host = HTTPHostExtractor.extract(bytes(pkt.payload))
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return
        
        if pkt.tuple.dst_port == 53 or pkt.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return
        
        if pkt.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif pkt.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


class LoadBalancer:
    def __init__(self, id: int, fps: List[FastPath]):
        self.id = id
        self.fps = fps
        self.num_fps = len(fps)
        self.dispatched = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._input_queue: queue.Queue = queue.Queue(maxsize=10000)
    
    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
    
    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
    
    def get_queue(self) -> queue.Queue:
        return self._input_queue
    
    def get_dispatched(self) -> int:
        return self.dispatched
    
    def _run(self):
        while self._running:
            try:
                pkt = self._input_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            
            fp_idx = pkt.tuple.hash() % self.num_fps
            self.fps[fp_idx].get_queue().put(pkt)
            self.dispatched += 1


class DPIEngine:
    def __init__(self, num_lbs: int = 2, fps_per_lb: int = 2):
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        total_fps = num_lbs * fps_per_lb
        
        print()
        print("+==============================================================+")
        print("|              DPI ENGINE v2.0 (Python - Multi-threaded)      |")
        print("+==============================================================+")
        print(f"| Load Balancers: {num_lbs:2d}    FPs per LB: {fps_per_lb:2d}    Total FPs: {total_fps:2d}     |")
        print("+==============================================================+")
        print()
        
        self.rules = BlockingRules()
        self.stats = Stats()
        self.output_queue: queue.Queue = queue.Queue(maxsize=10000)
        
        self.fps: List[FastPath] = []
        for i in range(total_fps):
            fp = FastPath(i, self.rules, self.stats, self.output_queue)
            self.fps.append(fp)
        
        self.lbs: List[LoadBalancer] = []
        for lb_id in range(num_lbs):
            start = lb_id * fps_per_lb
            lb_fps = self.fps[start:start + fps_per_lb]
            lb = LoadBalancer(lb_id, lb_fps)
            self.lbs.append(lb)
    
    def block_ip(self, ip: str):
        self.rules.block_ip(ip)
    
    def block_app(self, app: str):
        self.rules.block_app(app)
    
    def block_domain(self, domain: str):
        self.rules.block_domain(domain)
    
    def process(self, input_file: str, output_file: str) -> bool:
        print("[Reader] Processing packets...")
        
        try:
            pcap_reader = PcapReader(input_file)
        except Exception as e:
            print(f"Error reading PCAP: {e}")
            return False
        
        for fp in self.fps:
            fp.start()
        
        for lb in self.lbs:
            lb.start()
        
        output_thread = threading.Thread(target=self._output_writer, args=(output_file,), daemon=True)
        output_thread.start()
        
        pkt_id = 0
        for pcap_pkt in pcap_reader.packets:
            parsed = PacketParser.parse_packet(pcap_pkt.data)
            
            if not parsed['valid']:
                continue
            
            if parsed['protocol'] not in (6, 17):
                continue
            
            pkt = Packet(
                id=pkt_id,
                ts_sec=pcap_pkt.ts_sec,
                ts_usec=pcap_pkt.ts_usec,
                tuple=FiveTuple(
                    src_ip=parsed['src_ip'],
                    dst_ip=parsed['dst_ip'],
                    src_port=parsed['src_port'],
                    dst_port=parsed['dst_port'],
                    protocol=parsed['protocol']
                ),
                raw_data=pcap_pkt.data,
                payload=parsed['payload'],
                tcp_flags=parsed['tcp_flags']
            )
            
            self.stats.total_packets += 1
            self.stats.total_bytes += len(pcap_pkt.data)
            
            if parsed['protocol'] == 6:
                self.stats.tcp_packets += 1
            else:
                self.stats.udp_packets += 1
            
            lb_idx = pkt.tuple.hash() % len(self.lbs)
            try:
                self.lbs[lb_idx].get_queue().put_nowait(pkt)
            except queue.Full:
                pass
            
            pkt_id += 1
        
        print(f"[Reader] Done reading {pkt_id} packets")
        
        import time
        time.sleep(0.5)
        
        for lb in self.lbs:
            lb.stop()
        
        for fp in self.fps:
            fp.stop()
        
        self.output_queue.put(None)
        output_thread.join(timeout=2)
        
        self._print_report()
        
        print(f"\nOutput written to: {output_file}")
        return True
    
    def _output_writer(self, output_file: str):
        writer = PcapWriter(output_file)
        
        while True:
            try:
                pkt = self.output_queue.get(timeout=1)
                if pkt is None:
                    break
                writer.write(PcapPacket(ts_sec=pkt.ts_sec, ts_usec=pkt.ts_usec, data=pkt.raw_data))
            except queue.Empty:
                break
        
        writer.close()
    
    def _print_report(self):
        from dpi_types import APP_NAMES
        
        print()
        print("+==============================================================+")
        print("|                      PROCESSING REPORT                        |")
        print("+==============================================================+")
        print(f"| Total Packets:      {self.stats.total_packets:12d}                           |")
        print(f"| Total Bytes:        {self.stats.total_bytes:12d}                           |")
        print(f"| TCP Packets:        {self.stats.tcp_packets:12d}                           |")
        print(f"| UDP Packets:        {self.stats.udp_packets:12d}                           |")
        print("+==============================================================+")
        print(f"| Forwarded:          {self.stats.forwarded:12d}                           |")
        print(f"| Dropped:            {self.stats.dropped:12d}                           |")
        
        print("+==============================================================+")
        print("| THREAD STATISTICS                                             |")
        for i, lb in enumerate(self.lbs):
            print(f"|   LB{i} dispatched:   {lb.get_dispatched():12d}                           |")
        for i, fp in enumerate(self.fps):
            print(f"|   FP{i} processed:    {fp.get_processed():12d}                           |")
        
        print("+==============================================================+")
        print("|                   APPLICATION BREAKDOWN                       |")
        print("+==============================================================+")
        
        sorted_apps = sorted(self.stats.app_counts.items(), key=lambda x: x[1], reverse=True)
        
        for app_type, count in sorted_apps:
            pct = 100.0 * count / self.stats.total_packets if self.stats.total_packets > 0 else 0
            bar_len = int(pct / 5)
            bar = '#' * bar_len
            name = APP_NAMES.get(app_type, "Unknown")
            print(f"| {name:15s}{count:8d} {pct:5.1f}% {bar:20s}  |")
        
        print("+==============================================================+")
        
        if self.stats.detected_snis:
            print("\n[Detected Domains/SNIs]")
            for sni, app in self.stats.detected_snis.items():
                print(f"  - {sni} -> {APP_NAMES.get(app, 'Unknown')}")


def print_usage():
    print("""
DPI Engine v2.0 - Deep Packet Inspection (Python)
================================================

Usage: python main.py <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)

Example:
  python main.py capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")
