package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server        ServerConfig   `toml:"server"`
	SSL           SSLConfig      `toml:"ssl"`
	Authorization AuthConfig     `toml:"authorization"`
	IPv6Pools     IPv6PoolConfig `toml:"ipv6_pools"`
}

type ServerConfig struct {
	ListenPort      string `toml:"listen_port"`
	ListenPortHttps string `toml:"listen_port_https"`
	MaxConnections  int    `toml:"max_connections"`
	IdleTimeoutSec  int    `toml:"idle_timeout_seconds"`
	ReadTimeoutSec  int    `toml:"read_timeout_seconds"`
	WriteTimeoutSec int    `toml:"write_timeout_seconds"`
}

type SSLConfig struct {
	Enabled  bool   `toml:"enabled"`
	CertPath string `toml:"cert_path"`
	KeyPath  string `toml:"key_path"`
}

type AuthConfig struct {
	AllowedIPs []string `toml:"allowed_ips"`
}

type IPv6PoolConfig struct {
	Subnets            []string `toml:"subnets"`
	AddressesPerSubnet int      `toml:"addresses_per_subnet"`
	ExcludeAddresses   []string `toml:"exclude_addresses"`
}

type IPRange struct {
	ip    net.IP
	ipNet *net.IPNet
	start net.IP
	end   net.IP
}

type ProxyServer struct {
	Config        *Config
	ReverseProxy  *httputil.ReverseProxy
	IPv6Addresses []net.IP
	AllowedRanges []*IPRange
	mu            sync.RWMutex

	ServedRequests int64
	requestCount   int64
}

func main() {
	cfg, err := loadConfig("config.toml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	proxy := NewProxyServer(cfg)
	go proxy.startStatsPrinter()

	go func() {
		log.Printf("Starting HTTP server on %s", cfg.Server.ListenPort)
		if err := http.ListenAndServe(":"+cfg.Server.ListenPort, proxy); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	if cfg.SSL.Enabled {
		go func() {
			log.Printf("Starting HTTPS server on %s", cfg.Server.ListenPortHttps)
			server := &http.Server{
				Addr:         ":" + cfg.Server.ListenPortHttps,
				Handler:      proxy,
				TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			}
			if err := server.ListenAndServeTLS(cfg.SSL.CertPath, cfg.SSL.KeyPath); err != nil {
				log.Fatalf("HTTPS server failed: %v", err)
			}
		}()
	}

	select {}
}

func parseIPRange(ipStr string) (*IPRange, error) {
	if ip := net.ParseIP(ipStr); ip != nil {
		return &IPRange{ip: ip}, nil
	}
	if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
		return &IPRange{ipNet: ipNet}, nil
	}
	if parts := strings.Split(ipStr, "-"); len(parts) == 2 {
		start := net.ParseIP(parts[0])
		end := net.ParseIP(parts[1])
		if start != nil && end != nil {
			return &IPRange{start: start, end: end}, nil
		}
	}

	return nil, errors.New("invalid IP format")
}

func (r *IPRange) Contains(ip net.IP) bool {
	if r.ip != nil {
		return r.ip.Equal(ip)
	}
	if r.ipNet != nil {
		return r.ipNet.Contains(ip)
	}
	if r.start != nil && r.end != nil {
		return bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) <= 0
	}
	return false
}

func loadConfig(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func NewProxyServer(cfg *Config) *ProxyServer {
	proxy := &ProxyServer{
		Config: cfg,
	}

	for _, ipStr := range cfg.Authorization.AllowedIPs {
		if ipStr == "*" {
			proxy.AllowedRanges = nil
			break
		}
		ipRange, err := parseIPRange(ipStr)
		if err == nil {
			proxy.AllowedRanges = append(proxy.AllowedRanges, ipRange)
		} else {
			log.Printf("Warning: Invalid IP format '%s' - %v", ipStr, err)
		}
	}

	proxy.generateIPv6Addresses()

	idleTimeout := time.Duration(cfg.Server.IdleTimeoutSec) * time.Second
	readTimeout := time.Duration(cfg.Server.ReadTimeoutSec) * time.Second

	proxy.ReverseProxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			if req.TLS != nil {
				req.URL.Scheme = "https"
			}
			req.URL.Host = req.Host
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   readTimeout,
				KeepAlive: idleTimeout,
				LocalAddr: proxy.getLocalAddr(),
			}).DialContext,
			MaxIdleConns:          cfg.Server.MaxConnections,
			IdleConnTimeout:       idleTimeout,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	return proxy
}

func (p *ProxyServer) generateIPv6Addresses() {
	excludeMap := make(map[string]struct{})
	for _, addr := range p.Config.IPv6Pools.ExcludeAddresses {
		excludeMap[addr] = struct{}{}
	}

	for _, entry := range p.Config.IPv6Pools.Subnets {
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				log.Printf("Invalid subnet: %s (%v)", entry, err)
				continue
			}

			ones, bits := ipNet.Mask.Size()
			hostBits := bits - ones
			totalIPs := uint64(1) << hostBits

			if p.Config.IPv6Pools.AddressesPerSubnet > 0 && totalIPs > uint64(p.Config.IPv6Pools.AddressesPerSubnet) {
				totalIPs = uint64(p.Config.IPv6Pools.AddressesPerSubnet)
			}

			for i := uint64(0); i < totalIPs; i++ {
				newIP := make(net.IP, len(ipNet.IP))
				copy(newIP, ipNet.IP)

				for j := 0; j < (hostBits+7)/8; j++ {
					bytePos := 16 - j - 1
					if bytePos < 0 {
						break
					}
					shift := uint(j * 8)
					newIP[bytePos] = byte((i >> shift) & 0xFF)
				}

				if _, excluded := excludeMap[newIP.String()]; excluded {
					continue
				}

				p.IPv6Addresses = append(p.IPv6Addresses, newIP)
			}
		} else {
			ip := net.ParseIP(entry)
			if ip == nil || ip.To16() == nil || ip.To4() != nil {
				log.Printf("Invalid IPv6 address: %s", entry)
				continue
			}

			if _, excluded := excludeMap[ip.String()]; excluded {
				continue
			}

			p.IPv6Addresses = append(p.IPv6Addresses, ip)
		}
	}
}

func (p *ProxyServer) getLocalAddr() net.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.IPv6Addresses) == 0 {
		return nil
	}

	idx := time.Now().UnixNano() % int64(len(p.IPv6Addresses))
	return &net.TCPAddr{
		IP:   p.IPv6Addresses[idx],
		Zone: "eth0",
		Port: 0,
	}
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&p.requestCount, 1)

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	if !p.isIPAuthorized(r.RemoteAddr) {
		log.Printf("Access denied for IP: %s", clientIP)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	outgoingAddr := p.getLocalAddr()
	//log.Printf("Connecting from %s to %s", outgoingAddr, r.Host)

	p.mu.Lock()
	p.ReverseProxy.Transport.(*http.Transport).DialContext = (&net.Dialer{
		Timeout:       time.Duration(p.Config.Server.ReadTimeoutSec) * time.Second,
		KeepAlive:     time.Duration(p.Config.Server.IdleTimeoutSec) * time.Second,
		LocalAddr:     outgoingAddr,
		FallbackDelay: -1000,
	}).DialContext
	p.mu.Unlock()

	p.ReverseProxy.ServeHTTP(w, r)
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	outgoingAddr := p.getLocalAddr()
	//log.Printf("HTTPS CONNECT from %s to %s", outgoingAddr, r.Host)

	dialer := &net.Dialer{
		Timeout:       10 * time.Second,
		LocalAddr:     outgoingAddr,
		FallbackDelay: -1000,
	}

	destConn, err := dialer.Dial("tcp6", r.Host)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", r.Host, err)
		http.Error(w, "Unable to connect to destination", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		destConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		destConn.Close()
		return
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func (p *ProxyServer) isIPAuthorized(remoteAddr string) bool {
	if p.AllowedRanges == nil {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, ipRange := range p.AllowedRanges {
		if ipRange.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *ProxyServer) startStatsPrinter() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		count := atomic.SwapInt64(&p.requestCount, 0)
		atomic.AddInt64(&p.ServedRequests, count)
		total := atomic.LoadInt64(&p.ServedRequests)
		clearConsole()
		printStatsBox(total, count, len(p.IPv6Addresses))
	}
}

func clearConsole() {
	fmt.Print("\033[H\033[2J")
}

func printStatsBox(served int64, perSec int64, ipv6Count int) {
	boxWidth := 30
	printLine := func() {
		fmt.Println("+" + strings.Repeat("-", boxWidth-2) + "+")
	}

	printLine()
	fmt.Printf("| %-26s |\n", "Proxy Server Stats")
	printLine()
	fmt.Printf("| Served requests: %-10d |\n", served)
	fmt.Printf("| Incoming req/s:  %-10d |\n", perSec)
	fmt.Printf("| IPv6 Addresses:  %-10d |\n", ipv6Count)
	printLine()
}
