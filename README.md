<!-- 
SEO Keywords: NullSec Network, network security tools, packet analyzer, port scanner,
network pentesting, TCP scanner, UDP scanner, ARP spoofer, network sniffer, MITM tools,
bad-antics, NullSec Framework, network hacking tools, traffic analyzer, network mapper
-->

<div align="center">

# 🌐 NullSec Network

### Advanced Network Security Toolkit

[![Discord](https://img.shields.io/badge/🔑_GET_KEYS-discord.gg/killers-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/killers)
[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/bad-antics)
[![License](https://img.shields.io/badge/License-NNET--XXX-red?style=for-the-badge)](LICENSE)

```
     ▓█████▄  ██▀███   ██▓ ██▓███      ███▄    █ ▓█████▄▄▄█████▓
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒   ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒  ▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░
     ░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒  ▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ 
     ░▒████▓ ░██▓ ▒██▒░██░▒██▒ ░  ░  ▒██░   ▓██░░▒████▒ ▒██▒ ░ 
      ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░  ░ ▒░   ▒ ▒ ░░ ▒░ ░ ▒ ░░   
      ░ ▒  ▒   ░▒ ░ ▒░ ▒ ░░▒ ░       ░ ░░   ░ ▒░ ░ ░  ░   ░    
        ░        ░     ░            ░   ░   ░       ░    ░      
     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
     █░░ PORT SCAN ░░░ PACKET SNIFF ░░░ ARP SPOOF ░░░ MITM ░░░█
     ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

### 🔓 **[Join discord.gg/killers](https://discord.gg/killers)** for premium features!

</div>

---

## 🎯 Features

| Tool | Language | Description | Free | Premium |
|------|----------|-------------|------|---------|
| **nullscan** | Go | Ultra-fast async port scanner | ✅ | 🔥 |
| **netsniff** | Rust | Real-time packet analyzer | ✅ | 🔥 |
| **arpspoof** | C | ARP cache poisoning | ❌ | 🔥 |
| **netmap** | Go | Network topology mapper | ✅ | 🔥 |
| **tcpdump++** | Rust | Enhanced traffic capture | ✅ | 🔥 |
| **dnsspoof** | Python | DNS spoofing toolkit | ❌ | 🔥 |

---

## 📁 Structure

```
nullsec-network/
├── go/
│   ├── nullscan/        # Async port scanner (10k ports/sec)
│   ├── netmap/          # Network topology mapper
│   └── bannerGrab/      # Service banner grabber
├── rust/
│   ├── netsniff/        # Packet analyzer
│   ├── tcpdump_plus/    # Enhanced tcpdump
│   └── flowtrack/       # Connection tracker
├── python/
│   ├── dnsspoof.py      # DNS spoofing
│   ├── arpwatch.py      # ARP monitoring
│   └── netrecon.py      # Network reconnaissance
└── scripts/
    ├── setup_monitor.sh # Monitor mode setup
    └── fw_bypass.sh     # Firewall bypass techniques
```

---

## 🚀 Quick Start

```bash
# Install Go tools
cd go/nullscan && go build -o nullscan
./nullscan -target 192.168.1.0/24 -ports 1-65535 -threads 1000

# Install Rust tools  
cd rust/netsniff && cargo build --release
sudo ./target/release/netsniff -i eth0 -f "tcp port 80"

# Python tools
pip install scapy netifaces
python3 python/dnsspoof.py -i eth0 -t 192.168.1.100
```

---

## 🔧 Tool Details

### nullscan (Go) - Blazing Fast Port Scanner

```go
// Scan 65535 ports in under 30 seconds
nullscan -t 10.0.0.1 -p 1-65535 --rate 50000

// Output formats: json, xml, csv, grep
nullscan -t 192.168.1.0/24 -p 22,80,443 -o json > scan.json

// Service detection + banner grab
nullscan -t target.com -sV --scripts=default
```

### netsniff (Rust) - Packet Analyzer

```bash
# Capture HTTP traffic
sudo netsniff -i eth0 -f "tcp port 80" --decode

# Extract credentials (Premium)
sudo netsniff -i eth0 --extract-creds -o creds.txt

# PCAP export
sudo netsniff -i eth0 -w capture.pcap -c 10000
```

---

## ⚠️ Legal Disclaimer

**For authorized security testing only.** Unauthorized network scanning or interception is illegal. Always obtain written permission before testing.

---

<div align="center">

**NullSec Framework** | [GitHub](https://github.com/bad-antics) | [Discord](https://discord.gg/killers)

</div>
