package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/wfdewith/cldaproxy/internal/proxy"
)

func main() {
	ip := flag.String("ip", "127.0.0.1", "listen IP")
	port := flag.Int("port", 3890, "listen port")
	flag.Parse()

	ipaddr := net.ParseIP(*ip)
	if ipaddr == nil {
		fmt.Printf("invalid IP address: %q\n", *ip)
		os.Exit(1)
	}

	if *port < 1 || *port > 65535 {
		fmt.Printf("port must be in range 1-65535, got %d\n", *port)
		os.Exit(1)
	}

	proxy := proxy.New(ipaddr, *port)
	proxy.Start()
}
