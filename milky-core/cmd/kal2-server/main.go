// kal2-server: production binary for the kal2 egress host.
//
//	kal2-server -listen :443 -domain kal.example.dev -cert fullchain.pem \
//	  -key privkey.pem -user uid=pskb64 [-user ...] [-decoy /var/www] [-steal host:port]
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/carrier"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/core"
	"github.com/Frtertaer/milkyvpn/milky-core/pkg/kal2core"
)

// certMapFlags collects -domain-cert name=cert.pem:key.pem pairs.
type certMapFlags map[string][2]string

func (c certMapFlags) String() string { return fmt.Sprint(map[string][2]string(c)) }
func (c certMapFlags) Set(v string) error {
	name, pair, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("domain-cert must be name=cert.pem:key.pem")
	}
	cf, kf, ok := strings.Cut(pair, ":")
	if !ok || name == "" || cf == "" || kf == "" {
		return fmt.Errorf("domain-cert must be name=cert.pem:key.pem")
	}
	c[strings.ToLower(strings.TrimSpace(name))] = [2]string{cf, kf}
	return nil
}

type userFlags []kal2core.User

func (u *userFlags) String() string { return fmt.Sprint(*u) }
func (u *userFlags) Set(v string) error {
	id, psk, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("user must be id=psk")
	}
	k, err := kal2core.DecodeKey(psk)
	if err != nil {
		return fmt.Errorf("user %s: %w", id, err)
	}
	*u = append(*u, kal2core.User{ID: id, PSK: k})
	return nil
}

func main() {
	listen := flag.String("listen", ":443", "listen addr (or \"off\" for a UDP-only server)")
	udpListen := flag.String("udp-listen", "", "quasar UDP/KCP listen addr (e.g. :20443)")
	quic2Listen := flag.String("quic2-listen", "", "quic2 (QUIC v2) UDP listen addr (e.g. :20444)")
	rtcListen := flag.String("rtc-listen", "", "rtc (WebRTC-shaped) UDP listen addr (e.g. :20445) — quasar inside valid RTP packets")
	frontListen := flag.String("front-listen", "", "plain-HTTP listen addr for front relays (e.g. :8081) — a serverless function/CDN worker forwards here; no TLS on this leg")
	udpFEC := flag.String("udp-fec", "0,0", "quasar Reed-Solomon FEC shards data,parity (e.g. 10,3)")
	udpWnd := flag.Int("udp-sndwnd", 0, "quasar KCP send window in segments; bounds the in-flight backlog (0 = 16384)")
	udpRes := flag.Int("udp-resend", 0, "quasar KCP dup-ack fast-retransmit threshold (0 = RTO only)")
	udpRate := flag.Int("udp-rate", 0, "quasar packet output rate cap in Mbit/s (0 = unlimited)")
	domain := flag.String("domain", "", "our TLS domain (comma list = decoy pool; first is primary)")
	cert := flag.String("cert", "", "fullchain PEM")
	key := flag.String("key", "", "private key PEM")
	var domainCerts certMapFlags
	flag.Var(&domainCerts, "domain-cert", "extra domain file cert: name=cert.pem:key.pem (repeatable, decoy pool)")
	stealMap := flag.String("steal-map", "", "per-SNI splice targets: sni=host:port,... (tried before -steal)")
	autocertDir := flag.String("autocert", "", "ACME cache dir (Let's Encrypt HTTP-01 on :80)")
	autocertHTTP := flag.String("autocert-addr", ":80", "ACME HTTP-01 listen addr")
	identity := flag.String("identity", "", "server ed25519 private key (hex)")
	steal := flag.String("steal", "", "foreign-SNI decoy upstream host:port")
	decoy := flag.String("decoy", "", "decoy site directory")
	driftPath := flag.String("drift", "", "drift carrier path")
	egressFamily := flag.String("egress-family", "dual", "egress IP family: dual|prefer4|only4")
	upstream := flag.String("upstream", "", "chain egress via socks5://[user:pass@]host:port")
	upstreamOnly := flag.String("upstream-only", "", "comma domain suffixes routed via -upstream (empty=all)")
	var users userFlags
	flag.Var(&users, "user", "id=psk (repeatable)")
	usersFile := flag.String("users-file", "", "JSON file with users [{id,psk}] re-read on change — panel edits it, no restart needed")
	statsFile := flag.String("stats-file", "", "JSONL accounting log (session open/close with uid+bytes) for the panel")
	keygen := flag.Bool("keygen", false, "print a fresh ed25519 keypair and exit")
	echGen := flag.String("echgen", "", "generate an ECH config+key for this outer cover name (public_name), print the client ECHConfigList (b64, goes into kal2:// links as ech=) and write the key file to -echkeys-out")
	echKeysOut := flag.String("echkeys-out", "ech-keys.json", "key file written by -echgen")
	echKeys := flag.String("echkeys", "", "comma-separated ECH key files to serve (from -echgen)")
	flag.Parse()

	if *echGen != "" {
		list, k, err := carrier.GenerateECHConfig(*echGen)
		if err != nil {
			log.Fatal(err)
		}
		if err := carrier.SaveECHKeyFile(*echKeysOut, *echGen, k); err != nil {
			log.Fatal(err)
		}
		fmt.Println("ECHConfigList (base64, link param ech=):", base64.StdEncoding.EncodeToString(list))
		fmt.Println("key file written:", *echKeysOut)
		return
	}
	if *keygen {
		priv, pub, err := kal2core.GenerateKeypairHex()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("priv:", priv)
		fmt.Println("pub:", pub)
		return
	}
	fecD, fecP := 0, 0
	if *udpFEC != "0,0" {
		if _, err := fmt.Sscanf(*udpFEC, "%d,%d", &fecD, &fecP); err != nil || fecD < 0 || fecP < 0 {
			log.Fatalf("bad -udp-fec %q (want data,parity)", *udpFEC)
		}
	}
	udpOnly := *listen == "off"
	if *identity == "" || len(users) == 0 || (*udpListen == "" && *domain == "") || (!udpOnly && *cert == "" && *autocertDir == "") {
		log.Fatal("need -identity, at least one -user, and (-udp-listen or -domain); -cert/-key or -autocert unless -listen off")
	}
	idKey, err := hex.DecodeString(*identity)
	if err != nil || len(idKey) != ed25519.PrivateKeySize {
		log.Fatalf("bad -identity: need %d hex chars", ed25519.PrivateKeySize*2)
	}
	var eg *core.EgressConfig
	switch *egressFamily {
	case "prefer4":
		eg = &core.EgressConfig{PreferIPv4: true}
	case "only4":
		eg = &core.EgressConfig{OnlyIPv4: true}
	case "dual":
	default:
		log.Fatalf("bad -egress-family %q (dual|prefer4|only4)", *egressFamily)
	}
	if *upstream != "" {
		if eg == nil {
			eg = &core.EgressConfig{}
		}
		u, err := core.ParseUpstream(*upstream)
		if err != nil {
			log.Fatalf("bad -upstream: %v", err)
		}
		eg.Upstream = u
		if *upstreamOnly != "" {
			for _, s := range strings.Split(*upstreamOnly, ",") {
				if t := strings.TrimSpace(s); t != "" {
					eg.UpstreamOnly = append(eg.UpstreamOnly, t)
				}
			}
		}
	}
	domains := splitCommaStr(*domain)
	primary := ""
	var extras []string
	if len(domains) > 0 {
		primary = domains[0]
		extras = domains[1:]
	}
	var sm map[string]string
	if *stealMap != "" {
		sm = map[string]string{}
		for _, kv := range splitCommaStr(*stealMap) {
			k, t, ok := strings.Cut(kv, "=")
			if !ok || k == "" || t == "" {
				log.Fatalf("bad -steal-map entry %q (want sni=host:port)", kv)
			}
			sm[strings.ToLower(strings.TrimSuffix(k, "."))] = t
		}
	}
	err = kal2core.Serve(kal2core.ServerConfig{
		Listen:           *listen,
		UDPListen:        *udpListen,
		Quic2Listen:      *quic2Listen,
		RTCListen:        *rtcListen,
		FrontListen:      *frontListen,
		UDPFECData:       fecD,
		UDPFECParity:     fecP,
		UDPSndWnd:        *udpWnd,
		UDPResend:        *udpRes,
		UDPRate:          *udpRate * 125000,
		Domain:           primary,
		ExtraDomains:     extras,
		ExtraCertFiles:   domainCerts,
		StealMap:         sm,
		CertFile:         *cert,
		KeyFile:          *key,
		Identity:         idKey,
		AutocertDir:      *autocertDir,
		AutocertHTTPAddr: *autocertHTTP,
		StealAddr:        *steal,
		DecoyDir:         *decoy,
		DriftPath:        *driftPath,
		Users:            users,
		UsersFile:        *usersFile,
		StatsFile:        *statsFile,
		ECHKeyFiles:      splitCommaStr(*echKeys),
		Egress:           eg,
		Logf:             func(f string, a ...any) { log.Printf(f, a...) },
	})
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(0)
}

func splitCommaStr(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
