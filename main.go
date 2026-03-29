package main

import (
	"bufio"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	cnIPv4SparkIXNets []*net.IPNet
	cnIPv6SparkIXNets []*net.IPNet
	cnIPv6ISPNets     []*net.IPNet
)

// DNS cache entry with expiration
type cacheEntry struct {
	response  *dns.Msg
	expiresAt time.Time
}

// DNS response cache with concurrent access support
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		entries: make(map[string]*cacheEntry),
	}
}

// Get cached response if not expired
func (c *dnsCache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.response.Copy(), true
}

// Set cache entry with TTL
func (c *dnsCache) Set(key string, resp *dns.Msg, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		response:  resp.Copy(),
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// Clean expired entries
func (c *dnsCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

var cache = newDNSCache()

// Load IP list from file (generic loader for both IPv4 and IPv6)
func loadIPList(path string) ([]*net.IPNet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var nets []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("invalid CIDR skipped: %s\n", line)
			continue
		}
		nets = append(nets, ipNet)
	}
	return nets, scanner.Err()
}

// Check if IP is in the given network list
func isInIPNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// 查询上游 DNS
func queryDNS(r *dns.Msg, server string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}
	resp, _, err := c.Exchange(r, server)
	return resp, err
}

// Query DNS with EDNS Client Subnet
func queryDNSWithEDNS(r *dns.Msg, server string, clientSubnet string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Create a copy to avoid modifying the original request
	req := r.Copy()
	
	// Remove any existing EDNS0 records
	req.Extra = nil

	// Parse the client subnet IP
	ip := net.ParseIP(clientSubnet)
	if ip == nil {
		return nil, dns.ErrId
	}

	// Determine subnet size based on IP type
	var family uint16
	var sourceNetmask uint8
	if ip.To4() != nil {
		family = 1 // IPv4
		sourceNetmask = 24 // Use /24 for IPv4
	} else {
		family = 2 // IPv6
		sourceNetmask = 64 // Use /64 for IPv6
	}

	// Create EDNS0 subnet option
	e := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: sourceNetmask,
		SourceScope:   0,
		Address:       ip,
	}
	
	// Set EDNS0 using the SetEdns0 method
	req.SetEdns0(4096, false)
	
	// Add the subnet option to the OPT record
	if opt := req.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, e)
	}

	// Retry mechanism: try up to 3 times
	var resp *dns.Msg
	var err error
	for i := 0; i < 3; i++ {
		resp, _, err = c.Exchange(req, server)
		if err == nil {
			return resp, nil
		}
		if i < 2 {
			log.Printf("EDNS query attempt %d failed: %v, retrying...", i+1, err)
			time.Sleep(500 * time.Millisecond)
		}
	}
	return nil, err
}

// Get minimum TTL from DNS response
func getMinTTL(resp *dns.Msg) uint32 {
	if resp == nil || len(resp.Answer) == 0 {
		return 300 // Default 5 minutes
	}

	minTTL := uint32(3600) // Max 1 hour
	for _, ans := range resp.Answer {
		if ans.Header().Ttl < minTTL {
			minTTL = ans.Header().Ttl
		}
	}

	// Ensure minimum TTL of 60 seconds
	if minTTL < 60 {
		minTTL = 60
	}
	return minTTL
}

// Generate cache key from DNS question
func getCacheKey(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	q := r.Question[0]
	return q.Name + ":" + dns.TypeToString[q.Qtype]
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	primaryDNS := "119.29.29.29:53"
	fallbackDNS := "1.1.1.1:53"
	ednsClientSubnet := "183.61.225.70"

	// Check cache first
	cacheKey := getCacheKey(r)
	if cacheKey != "" {
		if cachedResp, found := cache.Get(cacheKey); found {
			log.Printf("Cache hit for %s", cacheKey)
			cachedResp.Id = r.Id // Update message ID to match request
			w.WriteMsg(cachedResp)
			return
		}
	}

	// Determine query type
	var queryType uint16
	if len(r.Question) > 0 {
		queryType = r.Question[0].Qtype
	}

	// Query primary DNS first
	resp, err := queryDNS(r, primaryDNS)
	if err != nil {
		log.Printf("primary DNS failed: %v, fallback to %s\n", err, fallbackDNS)
		resp, _ = queryDNS(r, fallbackDNS)
		if resp != nil && cacheKey != "" {
			cache.Set(cacheKey, resp, getMinTTL(resp))
		}
		w.WriteMsg(resp)
		return
	}

	// If client queries A record, also query AAAA to get complete information
	var aaaaResp *dns.Msg
	if queryType == dns.TypeA {
		aaaaQuery := r.Copy()
		aaaaQuery.Question[0].Qtype = dns.TypeAAAA
		aaaaResp, _ = queryDNS(aaaaQuery, primaryDNS)
	}

	// Check response for IPv6 and IPv4 records
	var hasIPv6 bool
	var hasIPv4 bool
	var ipv4InSparkIX bool
	var ipv6InSparkIX bool
	var ipv6InISP bool

	var ipv4Records []dns.RR
	var ipv6Records []dns.RR
	var ipv4SparkIXRecords []dns.RR
	var ipv6SparkIXRecords []dns.RR

	// Collect all IPv4 records from original response
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			hasIPv4 = true
			ipv4Records = append(ipv4Records, ans)
			if isInIPNets(a.A, cnIPv4SparkIXNets) {
				ipv4InSparkIX = true
				ipv4SparkIXRecords = append(ipv4SparkIXRecords, ans)
			}
		}
		if aaaa, ok := ans.(*dns.AAAA); ok {
			hasIPv6 = true
			ipv6Records = append(ipv6Records, ans)
			if isInIPNets(aaaa.AAAA, cnIPv6SparkIXNets) {
				ipv6InSparkIX = true
				ipv6SparkIXRecords = append(ipv6SparkIXRecords, ans)
			}
			if isInIPNets(aaaa.AAAA, cnIPv6ISPNets) {
				ipv6InISP = true
			}
		}
	}

	// If we queried AAAA separately, check those records too
	if aaaaResp != nil {
		for _, ans := range aaaaResp.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				hasIPv6 = true
				ipv6Records = append(ipv6Records, ans)
				if isInIPNets(aaaa.AAAA, cnIPv6SparkIXNets) {
					ipv6InSparkIX = true
					ipv6SparkIXRecords = append(ipv6SparkIXRecords, ans)
				}
				if isInIPNets(aaaa.AAAA, cnIPv6ISPNets) {
					ipv6InISP = true
				}
			}
		}
	}

	// Rule 1: Both IPv4 and IPv6 match SparkIX lists - return full response
	if ipv4InSparkIX && ipv6InSparkIX {
		log.Printf("Both IPv4 and IPv6 in SparkIX lists, returning SparkIX IPs only")
		filteredResp := new(dns.Msg)
		filteredResp.SetReply(r)
		// Include CNAME records
		for _, ans := range resp.Answer {
			if _, ok := ans.(*dns.CNAME); ok {
				filteredResp.Answer = append(filteredResp.Answer, ans)
			}
		}
		// Add only SparkIX IPv4 and IPv6 records
		filteredResp.Answer = append(filteredResp.Answer, ipv4SparkIXRecords...)
		filteredResp.Answer = append(filteredResp.Answer, ipv6SparkIXRecords...)
		if cacheKey != "" {
			cache.Set(cacheKey, filteredResp, getMinTTL(filteredResp))
		}
		w.WriteMsg(filteredResp)
		return
	}

	// Rule 2: Only IPv6 matches SparkIX list - return only IPv6
	if ipv6InSparkIX && !ipv4InSparkIX {
		log.Printf("Only IPv6 in SparkIX list, returning IPv6 only")
		filteredResp := new(dns.Msg)
		filteredResp.SetReply(r)
		// Include CNAME records from original response
		for _, ans := range resp.Answer {
			if _, ok := ans.(*dns.CNAME); ok {
				filteredResp.Answer = append(filteredResp.Answer, ans)
			}
		}
		filteredResp.Answer = append(filteredResp.Answer, ipv6SparkIXRecords...)
		if cacheKey != "" {
			cache.Set(cacheKey, filteredResp, getMinTTL(filteredResp))
		}
		w.WriteMsg(filteredResp)
		return
	}

	// Rule 3: Only IPv4 matches SparkIX list - return only IPv4 in SparkIX
	if ipv4InSparkIX && !ipv6InSparkIX {
		log.Printf("Only IPv4 in SparkIX list, returning SparkIX IPv4 only")
		filteredResp := new(dns.Msg)
		filteredResp.SetReply(r)
		// Include CNAME records
		for _, ans := range resp.Answer {
			if _, ok := ans.(*dns.CNAME); ok {
				filteredResp.Answer = append(filteredResp.Answer, ans)
			}
		}
		filteredResp.Answer = append(filteredResp.Answer, ipv4SparkIXRecords...)
		if cacheKey != "" {
			cache.Set(cacheKey, filteredResp, getMinTTL(filteredResp))
		}
		w.WriteMsg(filteredResp)
		return
	}

	// Rule 4: No match with SparkIX lists
	// If only IPv4 (no IPv6), fallback to 1.1.1.1
	if hasIPv4 && !hasIPv6 {
		log.Printf("Only IPv4 and not in SparkIX list, fallback to %s", fallbackDNS)
		resp, _ = queryDNS(r, fallbackDNS)
		if resp != nil && cacheKey != "" {
			cache.Set(cacheKey, resp, getMinTTL(resp))
		}
		w.WriteMsg(resp)
		return
	}

	// If has IPv6 but not in SparkIX list
	if hasIPv6 {
		// Check if IPv6 is in ISP list
		if ipv6InISP {
			// Re-query with EDNS and return only IPv6
			log.Printf("IPv6 in ISP list, re-querying with EDNS client subnet %s", ednsClientSubnet)
			
			// Create AAAA query for EDNS request
			ednsQuery := r.Copy()
			if queryType == dns.TypeA {
				ednsQuery.Question[0].Qtype = dns.TypeAAAA
			}
			
			ednsResp, err := queryDNSWithEDNS(ednsQuery, primaryDNS, ednsClientSubnet)
			
			// Use EDNS response if successful and contains IPv6
			var finalIPv6Records []dns.RR
			if err == nil && ednsResp != nil {
				for _, ans := range ednsResp.Answer {
					if _, ok := ans.(*dns.AAAA); ok {
						finalIPv6Records = append(finalIPv6Records, ans)
					}
				}
			}
			
			// If EDNS query failed or returned no IPv6, use original IPv6 records
			if len(finalIPv6Records) == 0 {
				if err != nil {
					log.Printf("EDNS query failed: %v, using original IPv6 records", err)
				} else {
					log.Printf("EDNS query returned no IPv6 records, using original IPv6 records")
				}
				finalIPv6Records = ipv6Records
			}

			// Filter response to include only IPv6 records
			filteredResp := new(dns.Msg)
			filteredResp.SetReply(r)
			// Include CNAME records
			for _, ans := range resp.Answer {
				if _, ok := ans.(*dns.CNAME); ok {
					filteredResp.Answer = append(filteredResp.Answer, ans)
				}
			}
			filteredResp.Answer = append(filteredResp.Answer, finalIPv6Records...)
			if cacheKey != "" {
				cache.Set(cacheKey, filteredResp, getMinTTL(filteredResp))
			}
			w.WriteMsg(filteredResp)
			return
		}

		// IPv6 exists but not in ISP list, fallback to 1.1.1.1
		log.Printf("IPv6 not in SparkIX or ISP list, fallback to %s", fallbackDNS)
		resp, _ = queryDNS(r, fallbackDNS)
		if resp != nil && cacheKey != "" {
			cache.Set(cacheKey, resp, getMinTTL(resp))
		}
		w.WriteMsg(resp)
		return
	}

	// Default: return original response
	if cacheKey != "" {
		cache.Set(cacheKey, resp, getMinTTL(resp))
	}
	w.WriteMsg(resp)
}

func main() {
	var err error
	cnIPv4SparkIXNets, err = loadIPList("cn-ipv4-sparkix.list")
	if err != nil {
		log.Fatalf("failed to load cn-ipv4-sparkix.list: %v", err)
	}
	cnIPv6SparkIXNets, err = loadIPList("cn-ipv6-sparkix.list")
	if err != nil {
		log.Fatalf("failed to load cn-ipv6-sparkix.list: %v", err)
	}
	cnIPv6ISPNets, err = loadIPList("cn-ipv6-isp.list")
	if err != nil {
		log.Fatalf("failed to load cn-ipv6-isp.list: %v", err)
	}

	// Start cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cache.CleanExpired()
			log.Println("Cache cleanup completed")
		}
	}()

	dns.HandleFunc(".", handleDNS)

	// UDP
	go func() {
		server := &dns.Server{
			Addr: ":5353",
			Net:  "udp",
		}
		log.Println("DNS server started on UDP :5353")
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("UDP server failed: %v", err)
		}
	}()

	// TCP
	server := &dns.Server{
		Addr: ":5353",
		Net:  "tcp",
	}
	log.Println("DNS server started on TCP :5353")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("TCP server failed: %v", err)
	}
}
