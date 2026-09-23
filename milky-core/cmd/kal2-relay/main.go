// kal2-relay: domestic relay — transparent TCP splice to the egress host.
// Deploy on an in-country host; clients point -addr at the relay.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/carrier"
)

func main() {
	listen := flag.String("listen", ":8443", "listen addr")
	upstream := flag.String("upstream", "", "egress host:port")
	flag.Parse()
	if *upstream == "" {
		log.Fatal("need -upstream")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("kal2-relay: %s -> %s", *listen, *upstream)
	log.Fatal(carrier.ServeRelay(ln, *upstream))
}
