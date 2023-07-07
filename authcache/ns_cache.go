package authcache

import (
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
)

// NS represents a cache entry
type NS struct {
	Servers *AuthServers
	DSRR    []dns.RR
	TTL     time.Duration

	ut time.Time
}

// NSCache type
type NSCache struct {
	cache *cache.Cache

	now func() time.Time
}

type Master struct {
	Name  string
	Zone  string
	Addrs []string
}

type MasterCache struct {
	cache *cache.Cache

	now func() time.Time
}

// NewMasterCache return new cache
func NewMasterCache() *MasterCache {
	n := &MasterCache{
		cache: cache.New(defaultCap),
		now:   time.Now,
	}

	return n
}

func (n *MasterCache) Get(zone string) (*Master, error) {
	key := cache.Hash(dns.Question{Name: zone, Qtype: dns.TypeA})
	el, ok := n.cache.Get(key)

	if !ok {
		return nil, cache.ErrCacheNotFound
	}

	return el.(*Master), nil
}

func (n *MasterCache) Set(master *Master) {
	key := cache.Hash(dns.Question{Name: master.Zone, Qtype: dns.TypeA})
	n.cache.Add(key, master)
}

// NewNSCache return new cache
func NewNSCache() *NSCache {
	n := &NSCache{
		cache: cache.New(defaultCap),
		now:   time.Now,
	}

	return n
}

// Get returns the entry for a key or an error
func (n *NSCache) Get(key uint64) (*NS, error) {
	el, ok := n.cache.Get(key)

	if !ok {
		return nil, cache.ErrCacheNotFound
	}

	ns := el.(*NS)

	elapsed := n.now().UTC().Sub(ns.ut)

	if elapsed >= ns.TTL {
		return nil, cache.ErrCacheExpired
	}

	return ns, nil
}

func (n *NSCache) GetWithExpired(key uint64) (*NS, bool) {
	if el, ok := n.cache.Get(key); ok {
		ns := el.(*NS)
		return ns, true
	} else {
		return nil, false
	}
}

// Set sets a keys value to a NS
func (n *NSCache) Set(key uint64, dsRR []dns.RR, servers *AuthServers, ttl time.Duration) {
	if ttl > maximumTTL {
		ttl = maximumTTL
	} else if ttl < minimumTTL {
		ttl = time.Duration(5) * time.Second
	}
	// Test expire name server cache
	//ttl = 10

	n.cache.Add(key, &NS{
		Servers: servers,
		DSRR:    dsRR,
		TTL:     ttl,
		ut:      n.now().UTC().Round(time.Second),
	})
}

// Remove remove a cache
func (n *NSCache) Remove(key uint64) {
	n.cache.Remove(key)
}

const (
	maximumTTL = 12 * time.Hour
	minimumTTL = 1 * time.Hour
	defaultCap = 1024 * 256
)
