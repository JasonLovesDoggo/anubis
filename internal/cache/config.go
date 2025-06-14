package cache

import "time"

// Cache configuration constants
const (
	DNSBLNumCounters = 1e6     // 1M counters for DNSBL cache
	DNSBLMaxCost     = 1 << 20 // 1MB max cost for DNSBL cache
	DNSBLBufferItems = 64      // buffer items for DNSBL cache
	DNSBLDefaultTTL  = 24 * time.Hour
)
