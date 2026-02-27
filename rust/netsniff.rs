/*
 * NetSniff - High-Performance Packet Analyzer
 * Author: bad-antics | GitHub: bad-antics | Discord: x.com/AnonAntics
 * License: NNET-XXX (Get key at x.com/AnonAntics)
 *
 *     ▓█████▄  ██▀███   ██▓ ██▓███      ██████  ███▄    █  ██▓  █████▒ █████▒
 *     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒  ▒██    ▒  ██ ▀█   █ ▓██▒▓██   ▒▓██   ▒ 
 *     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒  ░ ▓██▄   ▓██  ▀█ ██▒▒██▒▒████ ░▒████ ░ 
 */

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const VERSION: &str = "2.0.0";
const BANNER: &str = r#"
     ▓█████▄  ██▀███   ██▓ ██▓███      ██████  ███▄    █  ██▓  █████▒ █████▒
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒  ▒██    ▒  ██ ▀█   █ ▓██▒▓██   ▒▓██   ▒ 
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒  ░ ▓██▄   ▓██  ▀█ ██▒▒██▒▒████ ░▒████ ░ 
     ░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒    ▒   ██▒▓██▒  ▐▌██▒░██░░▓█▒  ░░▓█▒  ░ 
     ░▒████▓ ░██▓ ▒██▒░██░▒██▒ ░  ░  ▒██████▒▒▒██░   ▓██░░██░░▒█░   ░▒█░    
      ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░  ▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░▓   ▒ ░    ▒ ░    
     ══════════════════════════════════════════════════════════════════════
                   NetSniff v2.0 | github.com/bad-antics
     ══════════════════════════════════════════════════════════════════════
"#;

/// Packet statistics tracker
#[derive(Default)]
pub struct PacketStats {
    pub total_packets: AtomicU64,
    pub total_bytes: AtomicU64,
    pub tcp_packets: AtomicU64,
    pub udp_packets: AtomicU64,
    pub icmp_packets: AtomicU64,
    pub arp_packets: AtomicU64,
    pub other_packets: AtomicU64,
}

impl PacketStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_total(&self, bytes: u64) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn print_summary(&self) {
        println!("\n╔══════════════════════════════════════╗");
        println!("║         CAPTURE STATISTICS           ║");
        println!("╠══════════════════════════════════════╣");
        println!("║ Total Packets: {:>20} ║", self.total_packets.load(Ordering::Relaxed));
        println!("║ Total Bytes:   {:>20} ║", self.total_bytes.load(Ordering::Relaxed));
        println!("╠══════════════════════════════════════╣");
        println!("║ TCP:  {:>10} │ UDP:  {:>10} ║", 
            self.tcp_packets.load(Ordering::Relaxed),
            self.udp_packets.load(Ordering::Relaxed));
        println!("║ ICMP: {:>10} │ ARP:  {:>10} ║",
            self.icmp_packets.load(Ordering::Relaxed),
            self.arp_packets.load(Ordering::Relaxed));
        println!("║ Other:{:>10} │                    ║",
            self.other_packets.load(Ordering::Relaxed));
        println!("╚══════════════════════════════════════╝");
    }
}

/// Ethernet frame header
#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);
        
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        
        Some(Self { dst_mac, src_mac, ethertype })
    }

    pub fn format_mac(mac: &[u8; 6]) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
    }
}

/// IPv4 header
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let version = (data[0] >> 4) & 0x0F;
        let ihl = data[0] & 0x0F;
        
        if version != 4 || ihl < 5 {
            return None;
        }

        Some(Self {
            version,
            ihl,
            tos: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: (data[6] >> 5) & 0x07,
            fragment_offset: u16::from_be_bytes([data[6] & 0x1F, data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src_ip: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        })
    }

    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            47 => "GRE",
            50 => "ESP",
            51 => "AH",
            _ => "UNKNOWN",
        }
    }
}

/// TCP header
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: byte & 0x01 != 0,
            syn: byte & 0x02 != 0,
            rst: byte & 0x04 != 0,
            psh: byte & 0x08 != 0,
            ack: byte & 0x10 != 0,
            urg: byte & 0x20 != 0,
        }
    }

    pub fn to_string(&self) -> String {
        let mut flags = Vec::new();
        if self.syn { flags.push("SYN"); }
        if self.ack { flags.push("ACK"); }
        if self.fin { flags.push("FIN"); }
        if self.rst { flags.push("RST"); }
        if self.psh { flags.push("PSH"); }
        if self.urg { flags.push("URG"); }
        flags.join(",")
    }
}

impl TcpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        Some(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset: (data[12] >> 4) & 0x0F,
            flags: TcpFlags::from_byte(data[13]),
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
        })
    }
}

/// UDP header
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        Some(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }
}

/// Connection tracker for flow analysis
pub struct ConnectionTracker {
    connections: HashMap<String, ConnectionInfo>,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    pub fn track(&mut self, src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, protocol: &str, bytes: u64) {
        let key = format!("{}:{}-{}:{}-{}", src_ip, src_port, dst_ip, dst_port, protocol);
        
        self.connections
            .entry(key)
            .and_modify(|conn| {
                conn.packets += 1;
                conn.bytes += bytes;
                conn.last_seen = Instant::now();
            })
            .or_insert(ConnectionInfo {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol: protocol.to_string(),
                packets: 1,
                bytes,
                first_seen: Instant::now(),
                last_seen: Instant::now(),
            });
    }

    pub fn print_top_connections(&self, n: usize) {
        let mut conns: Vec<_> = self.connections.values().collect();
        conns.sort_by(|a, b| b.bytes.cmp(&a.bytes));

        println!("\n╔═══════════════════════════════════════════════════════════════════════════╗");
        println!("║                          TOP {} CONNECTIONS                                ║", n);
        println!("╠═══════════════════════════════════════════════════════════════════════════╣");
        
        for (i, conn) in conns.iter().take(n).enumerate() {
            println!("║ {:2}. {}:{} → {}:{} ({}) ",
                i + 1,
                conn.src_ip, conn.src_port,
                conn.dst_ip, conn.dst_port,
                conn.protocol);
            println!("║     Packets: {} | Bytes: {} | Duration: {:?}",
                conn.packets, conn.bytes,
                conn.last_seen.duration_since(conn.first_seen));
        }
        println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    }
}

/// Credential patterns for extraction (Premium feature)
pub struct CredentialExtractor {
    patterns: Vec<(&'static str, regex::Regex)>,
}

impl CredentialExtractor {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // HTTP Basic Auth
                ("HTTP Basic", regex::Regex::new(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)").unwrap()),
                // FTP credentials
                ("FTP User", regex::Regex::new(r"USER\s+(\S+)").unwrap()),
                ("FTP Pass", regex::Regex::new(r"PASS\s+(\S+)").unwrap()),
                // HTTP Form data
                ("Form Password", regex::Regex::new(r"(?:password|passwd|pwd)=([^&\s]+)").unwrap()),
                ("Form Username", regex::Regex::new(r"(?:username|user|login|email)=([^&\s]+)").unwrap()),
                // SMTP Auth
                ("SMTP Auth", regex::Regex::new(r"AUTH\s+(?:LOGIN|PLAIN)\s+([A-Za-z0-9+/=]+)").unwrap()),
            ],
        }
    }

    pub fn extract(&self, payload: &str) -> Vec<(String, String)> {
        let mut found = Vec::new();
        
        for (name, pattern) in &self.patterns {
            for cap in pattern.captures_iter(payload) {
                if let Some(m) = cap.get(1) {
                    found.push((name.to_string(), m.as_str().to_string()));
                }
            }
        }
        
        found
    }
}

/// Print packet info
pub fn print_packet(
    timestamp: &str,
    eth: &EthernetHeader,
    ip: Option<&Ipv4Header>,
    tcp: Option<&TcpHeader>,
    udp: Option<&UdpHeader>,
    len: usize,
) {
    print!("{} ", timestamp);
    
    if let Some(ip_hdr) = ip {
        if let Some(tcp_hdr) = tcp {
            println!(
                "TCP {}:{} → {}:{} [{}] Seq={} Ack={} Win={} Len={}",
                ip_hdr.src_ip, tcp_hdr.src_port,
                ip_hdr.dst_ip, tcp_hdr.dst_port,
                tcp_hdr.flags.to_string(),
                tcp_hdr.seq_num,
                tcp_hdr.ack_num,
                tcp_hdr.window,
                len
            );
        } else if let Some(udp_hdr) = udp {
            println!(
                "UDP {}:{} → {}:{} Len={}",
                ip_hdr.src_ip, udp_hdr.src_port,
                ip_hdr.dst_ip, udp_hdr.dst_port,
                udp_hdr.length
            );
        } else {
            println!(
                "{} {} → {} Len={}",
                ip_hdr.protocol_name(),
                ip_hdr.src_ip,
                ip_hdr.dst_ip,
                len
            );
        }
    } else {
        println!(
            "ETH {} → {} Type=0x{:04x} Len={}",
            EthernetHeader::format_mac(&eth.src_mac),
            EthernetHeader::format_mac(&eth.dst_mac),
            eth.ethertype,
            len
        );
    }
}

fn main() {
    println!("{}", BANNER);
    
    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        println!("Usage: netsniff [OPTIONS]");
        println!();
        println!("Options:");
        println!("  -i, --interface <IFACE>   Network interface to capture on");
        println!("  -f, --filter <FILTER>     BPF filter expression");
        println!("  -c, --count <NUM>         Number of packets to capture");
        println!("  -w, --write <FILE>        Write packets to PCAP file");
        println!("  -x, --hex                 Show hex dump of packets");
        println!("  --extract-creds           Extract credentials (Premium)");
        println!("  --flow                    Track connection flows");
        println!("  -v, --version             Show version");
        println!();
        println!("Examples:");
        println!("  sudo netsniff -i eth0");
        println!("  sudo netsniff -i eth0 -f \"tcp port 80\"");
        println!("  sudo netsniff -i eth0 -c 1000 -w capture.pcap");
        println!();
        println!("Get premium at x.com/AnonAntics");
        return;
    }

    if args.contains(&"-v".to_string()) || args.contains(&"--version".to_string()) {
        println!("NetSniff v{}", VERSION);
        println!("github.com/bad-antics | x.com/AnonAntics");
        return;
    }

    // Demo mode - show what would be captured
    println!("[*] NetSniff requires root privileges and libpcap");
    println!("[*] Build with: cargo build --release --features pcap");
    println!();
    println!("[*] Demo Mode - Simulated Packet Output:");
    println!("════════════════════════════════════════════════════════════════");
    
    // Simulated packet output
    let demo_packets = vec![
        "12:34:56.789 TCP 192.168.1.100:54321 → 93.184.216.34:443 [SYN] Seq=0 Ack=0 Win=65535 Len=0",
        "12:34:56.812 TCP 93.184.216.34:443 → 192.168.1.100:54321 [SYN,ACK] Seq=0 Ack=1 Win=65535 Len=0",
        "12:34:56.813 TCP 192.168.1.100:54321 → 93.184.216.34:443 [ACK] Seq=1 Ack=1 Win=65535 Len=0",
        "12:34:56.850 TCP 192.168.1.100:54321 → 93.184.216.34:443 [PSH,ACK] Seq=1 Ack=1 Win=65535 Len=517",
        "12:34:56.923 UDP 192.168.1.100:53421 → 8.8.8.8:53 Len=45",
        "12:34:56.956 UDP 8.8.8.8:53 → 192.168.1.100:53421 Len=78",
    ];

    for packet in demo_packets {
        println!("{}", packet);
        std::thread::sleep(Duration::from_millis(100));
    }

    // Show stats
    let stats = PacketStats::new();
    stats.total_packets.store(6, Ordering::Relaxed);
    stats.total_bytes.store(1845, Ordering::Relaxed);
    stats.tcp_packets.store(4, Ordering::Relaxed);
    stats.udp_packets.store(2, Ordering::Relaxed);
    stats.print_summary();

    println!("\n[*] For full functionality, compile with libpcap support");
    println!("[*] Get premium features at x.com/AnonAntics");
}
