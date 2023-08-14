package authcache

import (
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"reflect"
	"time"
)

const (
	DefaultTTL = 10000
)

type AnchorNs struct {
	Name string
	Ips  map[string]interface{}
}

type AnchorNsSet struct {
	Zone string
	Nss  map[string]AnchorNs
	DSRR []dns.RR
	TTL  time.Duration

	ut time.Time
}

func (n AnchorNsSet) Equal(other AnchorNsSet) bool {
	return reflect.DeepEqual(n, other)
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
	n.cache.Add(key, &ns)
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
