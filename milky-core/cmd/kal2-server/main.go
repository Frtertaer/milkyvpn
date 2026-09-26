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
	listen := flag.String("listen", ":443", "listen addr")
	domain := flag.String("domain", "", "our TLS domain")
	cert := flag.String("cert", "", "fullchain PEM")
	key := flag.String("key", "", "private key PEM")
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
	if *domain == "" || *identity == "" || len(users) == 0 || (*cert == "" && *autocertDir == "") {
		log.Fatal("need -domain, -identity, at least one -user and (-cert/-key or -autocert)")
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
	err = kal2core.Serve(kal2core.ServerConfig{
		Listen:           *listen,
		Domain:           *domain,
		CertFile:         *cert,
		KeyFile:          *key,
		Identity:         idKey,
		AutocertDir:      *autocertDir,
		AutocertHTTPAddr: *autocertHTTP,
		StealAddr:        *steal,
		DecoyDir:         *decoy,
		DriftPath:        *driftPath,
		Users:            users,
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
