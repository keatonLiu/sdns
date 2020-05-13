package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/semihalev/log"
)

// Config type
type Config struct {
	Version         string
	BlockLists      []string
	BlockListDir    string
	RootServers     []string
	Root6Servers    []string
	RootKeys        []string
	FallbackServers []string
	AccessList      []string
	LogLevel        string
	AccessLog       string
	Bind            string
	BindTLS         string
	BindDOH         string
	TLSCertificate  string
	TLSPrivateKey   string
	API             string
	Nullroute       string
	Nullroutev6     string
	Hostsfile       string
	OutboundIPs     []string
	OutboundIP6s    []string
	Timeout         Duration
	Expire          uint32
	CacheSize       int
	Maxdepth        int
	RateLimit       int
	ClientRateLimit int
	CookieSecret    string
	NSID            string
	Blocklist       []string
	Whitelist       []string
	Chaos           bool

	sVersion string
}

// ServerVersion return current server version
func (c *Config) ServerVersion() string {
	return c.sVersion
}

// Duration type
type Duration struct {
	time.Duration
}

// UnmarshalText for duration type
func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

var defaultConfig = `
# config version, config and build versions can be different.
version = "%s"

# address to bind to for the DNS server
bind = ":53"

# address to bind to for the DNS-over-TLS server
# bindtls = ":853"

# address to bind to for the DNS-over-HTTPS server
# binddoh = ":8053"

# tls certificate file
# tlscertificate = "server.crt"

# tls private key file
# tlsprivatekey = "server.key"

# outbound ipv4 addresses, if you set multiple, sdns can use random outbound ipv4 address 
outboundips = [
]

# outbound ipv6 addresses, if you set multiple, sdns can use random outbound ipv6 address 
outboundip6s = [
]

# root zone ipv4 servers
rootservers = [
"192.5.5.241:53",
"198.41.0.4:53",
"192.228.79.201:53",
"192.33.4.12:53",
"199.7.91.13:53",
"192.203.230.10:53",
"192.112.36.4:53",
"128.63.2.53:53",
"192.36.148.17:53",
"192.58.128.30:53",
"193.0.14.129:53",
"199.7.83.42:53",
"202.12.27.33:53"
]

# root zone ipv6 servers
root6servers = [
"[2001:500:2f::f]:53",
"[2001:503:ba3e::2:30]:53",
"[2001:500:200::b]:53",
"[2001:500:2::c]:53",
"[2001:500:2d::d]:53",
"[2001:500:a8::e]:53",
"[2001:500:12::d0d]:53",
"[2001:500:1::53]:53",
"[2001:7fe::53]:53",
"[2001:503:c27::2:30]:53",
"[2001:7fd::1]:53",
"[2001:500:9f::42]:53",
"[2001:dc3::35]:53"
]

# root keys for dnssec
rootkeys = [
".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
]

# failover resolver ipv4 or ipv6 addresses with port, left blank for disabled. Example: "1.1.1.1:53"
fallbackservers = [
]

# address to bind to for the http API server, left blank for disabled
api = "127.0.0.1:8080"

# what kind of information should be logged, Log verbosity level [crit,error,warn,info,debug]
loglevel = "info"

# The location of access log file, left blank for disabled. SDNS uses Common Log Format by default.
# accesslog = ""

# list of remote blocklists
blocklists = [
"http://mirror1.malwaredomains.com/files/justdomains",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
"http://sysctl.org/cameleon/hosts",
"https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
"https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
"https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
"https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt"
]

# list of locations to recursively read blocklists from (warning, every file found is assumed to be a hosts-file or domain list)
blocklistdir = "bl"

# ipv4 address to forward blocked queries to
nullroute = "0.0.0.0"

# ipv6 address to forward blocked queries to
nullroutev6 = "::0"

# which clients allowed to make queries
accesslist = [
"0.0.0.0/0",
"::0/0"
]

# enables serving zone data from a hosts file, left blank for disabled
# the form of the entries in the /etc/hosts file are based on IETF RFC 952 which was updated by IETF RFC 1123.
hostsfile = ""

# query timeout for each dns lookups in duration
timeout = "5s"

# connect timeout for dns lookups in duration (deprecated, no longer used)
# connecttimeout = ""

# default error cache TTL in seconds
expire = 600

# cache size (total records in cache)
cachesize = 256000

# maximum recursion depth for nameservers
maxdepth = 30

# query based ratelimit per second, 0 for disabled
ratelimit = 0

# client ip address based ratelimit per minute, 0 for disabled
clientratelimit = 0

# manual blocklist entries
blocklist = []

# manual whitelist entries
whitelist = []

# DNS server identifier (RFC 5001), it's useful while operating multiple sdns. left blank for disabled
nsid = ""

# Enable to answer version.server, version.bind, hostname.bind, id.server chaos queries.
chaos = true
`

// Load loads the given config file
func Load(path, version string, sVersion string) (*Config, error) {
	config := new(Config)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if path == "sdns.conf" {
			// compatibility for old default conf file
			if _, err := os.Stat("sdns.toml"); os.IsNotExist(err) {
				if err := generateConfig(path, version); err != nil {
					return nil, err
				}
			} else {
				path = "sdns.toml"
			}
		}
	}

	log.Info("Loading config file", "path", path)

	if _, err := toml.DecodeFile(path, config); err != nil {
		return nil, fmt.Errorf("could not load config: %s", err)
	}

	if config.Version != version {
		log.Warn("Config file is out of version, you can generate new one and check the changes.")
	}

	config.sVersion = sVersion

	return config, nil
}

func generateConfig(path, version string) error {
	output, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("could not generate config: %s", err)
	}
	defer output.Close()

	r := strings.NewReader(fmt.Sprintf(defaultConfig, version))
	if _, err := io.Copy(output, r); err != nil {
		return fmt.Errorf("could not copy default config: %s", err)
	}

	if abs, err := filepath.Abs(path); err == nil {
		log.Info("Default config file generated", "config", abs)
	}

	return nil
}
