#!/usr/bin/env python3
import sys
import argparse
from dpi_engine import DPIEngine, print_usage


def main():
    parser = argparse.ArgumentParser(
        description="DPI Engine - Deep Packet Inspection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=argparse.SUPPRESS
    )
    
    parser.add_argument('input_pcap', nargs='?', help='Input PCAP file')
    parser.add_argument('output_pcap', nargs='?', help='Output PCAP file')
    parser.add_argument('--block-ip', action='append', help='Block source IP')
    parser.add_argument('--block-app', action='append', help='Block application')
    parser.add_argument('--block-domain', action='append', help='Block domain')
    parser.add_argument('--lbs', type=int, default=2, help='Number of load balancers')
    parser.add_argument('--fps', type=int, default=2, help='FP threads per LB')
    
    args = parser.parse_args()
    
    if not args.input_pcap or not args.output_pcap:
        print_usage()
        return 1
    
    engine = DPIEngine(num_lbs=args.lbs, fps_per_lb=args.fps)
    
    if args.block_ip:
        for ip in args.block_ip:
            engine.block_ip(ip)
    
    if args.block_app:
        for app in args.block_app:
            engine.block_app(app)
    
    if args.block_domain:
        for domain in args.block_domain:
            engine.block_domain(domain)
    
    success = engine.process(args.input_pcap, args.output_pcap)
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
