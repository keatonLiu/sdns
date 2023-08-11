package authcache

import (
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"time"
)

type AnchorNs struct {
	Name string
	A    []string
	AAAA []string
}

type AnchorNsSet struct {
	Zone string
	nss  []AnchorNs
	DSRR []dns.RR
	TTL  time.Duration

	ut time.Time
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

func (n *AnchorNsCache) Set(zone string, dsRR []dns.RR, servers []AnchorNs, ttl time.Duration) {
	key := cache.Hash(dns.Question{Name: zone, Qtype: dns.TypeNS, Qclass: dns.ClassINET})
	n.cache.Add(key, &AnchorNsSet{
		Zone: zone,
		nss:  servers,
		DSRR: dsRR,
		TTL:  ttl,
		ut:   n.now().UTC().Round(time.Second),
	})
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
		return nil, cache.ErrCacheExpired
	}
	return nss, nil
}
