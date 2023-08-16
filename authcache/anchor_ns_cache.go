package authcache

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"time"
)

const (
	DefaultTTL = 100 * time.Hour
)

type AnchorNs struct {
	Name string
	Ips  mapset.Set[string]
}

type AnchorNsSet struct {
	Zone string
	Nss  map[string]*AnchorNs
	TTL  time.Duration

	ut time.Time
}

func NewAnchorNsSet(zone string) *AnchorNsSet {
	return &AnchorNsSet{
		Zone: zone,
		TTL:  DefaultTTL,
		ut:   time.Now().UTC(),
		Nss:  map[string]*AnchorNs{},
	}
}

// AnchorNsCache type
type AnchorNsCache struct {
	cache *cache.Cache

	now func() time.Time
}

// NewAnchorNsCache return new cache
func NewAnchorNsCache() *AnchorNsCache {
	n := &AnchorNsCache{
		cache: cache.New(defaultCap),
		now:   time.Now,
	}

	return n
}

func (n *AnchorNsCache) Set(ns *AnchorNsSet) {
	key := cache.Hash(dns.Question{Name: ns.Zone, Qtype: dns.TypeNS, Qclass: dns.ClassINET})
	if ns.TTL == 0 {
		ns.TTL = DefaultTTL
	}
	ns.ut = time.Now()
	n.cache.Add(key, ns)
}

func (n *AnchorNsCache) Get(zone string) (*AnchorNsSet, error) {
	key := cache.Hash(dns.Question{Name: zone, Qtype: dns.TypeNS, Qclass: dns.ClassINET})
	el, ok := n.cache.Get(key)
	if !ok {
		return nil, cache.ErrCacheNotFound
	}
	nss := el.(*AnchorNsSet)
	elapsed := n.now().UTC().Sub(nss.ut)

	if elapsed >= nss.TTL {
		return nss, cache.ErrCacheExpired
	}
	return nss, nil
}
