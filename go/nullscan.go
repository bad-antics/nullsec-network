/*
 * NullScan - Ultra-fast Async Port Scanner
 * Author: bad-antics | GitHub: bad-antics | Twitter: x.com/AnonAntics
 * License: NNET-XXX (Get key at x.com/AnonAntics)
 *
 *     ▓█████▄  ██▀███   ██▓ ██▓███      ██████  ▄████▄   ▄▄▄       ███▄    █ 
 *     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒  ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
 *     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒  ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
 *     ░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒    ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
 *      ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░  ░        ░ ░   ░   ░ ▒░   ▒ ▒
 */

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	VERSION = "2.0.0"
	BANNER  = `
     ▓█████▄  ██▀███   ██▓ ██▓███      ██████  ▄████▄   ▄▄▄       ███▄    █ 
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒  ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒  ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
     ░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒    ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
     ░▒████▓ ░██▓ ▒██▒░██░▒██▒ ░  ░  ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
      ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
     ════════════════════════════════════════════════════════════════════════
                    NullScan v2.0 | github.com/bad-antics
     ════════════════════════════════════════════════════════════════════════`
)

// Common service ports mapping
var commonPorts = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
	143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
	5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
	8443: "https-alt", 27017: "mongodb", 6443: "kubernetes",
}

type ScanResult struct {
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	State     string    `json:"state"`
	Service   string    `json:"service,omitempty"`
	Banner    string    `json:"banner,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type Scanner struct {
	target      string
	ports       []int
	threads     int
	timeout     time.Duration
	results     []ScanResult
	mutex       sync.Mutex
	scanned     int64
	openPorts   int64
	grabBanner  bool
	outputFile  string
	outputFmt   string
}

func NewScanner(target string, ports []int, threads int, timeout time.Duration) *Scanner {
	return &Scanner{
		target:  target,
		ports:   ports,
		threads: threads,
		timeout: timeout,
		results: make([]ScanResult, 0),
	}
}

func (s *Scanner) ScanPort(ctx context.Context, host string, port int) *ScanResult {
	address := fmt.Sprintf("%s:%d", host, port)
	
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	result := &ScanResult{
		Host:      host,
		Port:      port,
		State:     "open",
		Timestamp: time.Now(),
	}

	// Service detection
	if service, ok := commonPorts[port]; ok {
		result.Service = service
	}

	// Banner grabbing (Premium feature simulation)
	if s.grabBanner {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		banner := make([]byte, 1024)
		n, _ := conn.Read(banner)
		if n > 0 {
			result.Banner = strings.TrimSpace(string(banner[:n]))
		}
	}

	return result
}

func (s *Scanner) Run(ctx context.Context) {
	fmt.Println(BANNER)
	fmt.Printf("\n[*] Target: %s\n", s.target)
	fmt.Printf("[*] Ports: %d\n", len(s.ports))
	fmt.Printf("[*] Threads: %d\n", s.threads)
	fmt.Printf("[*] Timeout: %v\n\n", s.timeout)

	startTime := time.Now()

	// Resolve target
	hosts := s.resolveTarget()
	if len(hosts) == 0 {
		fmt.Println("[-] Failed to resolve target")
		return
	}

	fmt.Printf("[+] Resolved %d host(s)\n", len(hosts))
	fmt.Println("[*] Scanning...")

	// Create work channel
	jobs := make(chan struct{ host string; port int }, s.threads*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					result := s.ScanPort(ctx, job.host, job.port)
					if result != nil {
						s.mutex.Lock()
						s.results = append(s.results, *result)
						s.mutex.Unlock()
						atomic.AddInt64(&s.openPorts, 1)
						fmt.Printf("[+] %s:%d OPEN (%s)\n", result.Host, result.Port, result.Service)
					}
					atomic.AddInt64(&s.scanned, 1)
				}
			}
		}()
	}

	// Send jobs
	for _, host := range hosts {
		for _, port := range s.ports {
			jobs <- struct{ host string; port int }{host, port}
		}
	}
	close(jobs)

	wg.Wait()

	elapsed := time.Since(startTime)
	fmt.Printf("\n[+] Scan completed in %v\n", elapsed)
	fmt.Printf("[+] Scanned: %d | Open: %d\n", atomic.LoadInt64(&s.scanned), atomic.LoadInt64(&s.openPorts))

	// Output results
	if s.outputFile != "" {
		s.saveResults()
	}
}

func (s *Scanner) resolveTarget() []string {
	var hosts []string

	// Check if CIDR
	if strings.Contains(s.target, "/") {
		_, ipnet, err := net.ParseCIDR(s.target)
		if err != nil {
			return hosts
		}
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			hosts = append(hosts, ip.String())
		}
		// Remove network and broadcast
		if len(hosts) > 2 {
			hosts = hosts[1 : len(hosts)-1]
		}
		return hosts
	}

	// Single IP or hostname
	ips, err := net.LookupIP(s.target)
	if err != nil {
		// Try as direct IP
		if ip := net.ParseIP(s.target); ip != nil {
			return []string{s.target}
		}
		return hosts
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			hosts = append(hosts, ip.String())
		}
	}
	return hosts
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (s *Scanner) saveResults() {
	sort.Slice(s.results, func(i, j int) bool {
		if s.results[i].Host == s.results[j].Host {
			return s.results[i].Port < s.results[j].Port
		}
		return s.results[i].Host < s.results[j].Host
	})

	var data []byte
	var err error

	switch s.outputFmt {
	case "json":
		data, err = json.MarshalIndent(s.results, "", "  ")
	default:
		var lines []string
		for _, r := range s.results {
			lines = append(lines, fmt.Sprintf("%s:%d\t%s\t%s", r.Host, r.Port, r.State, r.Service))
		}
		data = []byte(strings.Join(lines, "\n"))
	}

	if err != nil {
		fmt.Printf("[-] Error formatting output: %v\n", err)
		return
	}

	if err := os.WriteFile(s.outputFile, data, 0644); err != nil {
		fmt.Printf("[-] Error writing output: %v\n", err)
		return
	}
	fmt.Printf("[+] Results saved to %s\n", s.outputFile)
}

func parsePorts(portStr string) []int {
	var ports []int
	
	if portStr == "-" || portStr == "all" {
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports
	}

	if portStr == "common" || portStr == "top" {
		for port := range commonPorts {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		return ports
	}

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
				for i := start; i <= end; i++ {
					if i > 0 && i <= 65535 {
						ports = append(ports, i)
					}
				}
			}
		} else {
			port, _ := strconv.Atoi(part)
			if port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	return ports
}

func main() {
	target := flag.String("t", "", "Target (IP, hostname, or CIDR)")
	portStr := flag.String("p", "common", "Ports (1-1000, 22,80,443, common, all)")
	threads := flag.Int("threads", 500, "Number of concurrent threads")
	timeout := flag.Int("timeout", 1000, "Connection timeout in ms")
	banner := flag.Bool("sV", false, "Enable banner grabbing (Premium)")
	output := flag.String("o", "", "Output file")
	format := flag.String("f", "txt", "Output format (txt, json)")
	version := flag.Bool("v", false, "Show version")

	flag.Parse()

	if *version {
		fmt.Printf("NullScan v%s\n", VERSION)
		fmt.Println("github.com/bad-antics | x.com/AnonAntics")
		return
	}

	if *target == "" {
		fmt.Println(BANNER)
		fmt.Println("\nUsage: nullscan -t <target> [options]")
		fmt.Println("\nExamples:")
		fmt.Println("  nullscan -t 192.168.1.1 -p 1-1000")
		fmt.Println("  nullscan -t 10.0.0.0/24 -p common -threads 1000")
		fmt.Println("  nullscan -t target.com -p all -sV -o results.json -f json")
		fmt.Println("\nGet premium key at x.com/AnonAntics")
		return
	}

	ports := parsePorts(*portStr)
	if len(ports) == 0 {
		fmt.Println("[-] No valid ports specified")
		return
	}

	scanner := NewScanner(*target, ports, *threads, time.Duration(*timeout)*time.Millisecond)
	scanner.grabBanner = *banner
	scanner.outputFile = *output
	scanner.outputFmt = *format

	ctx := context.Background()
	scanner.Run(ctx)
}
