package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/wfdewith/cldaproxy/internal/proxy"
)

func main() {
	ip := flag.String("ip", "127.0.0.1", "listen IP")
	port := flag.Int("port", 3890, "listen port")
	timeout := flag.Int("timeout", 5, "timeout in seconds for communicating with upstream")
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

	if *timeout < 0 {
		fmt.Printf("timeout must be greater than 0, got %d\n", *timeout)
		os.Exit(1)
	}

	proxy := proxy.New(ipaddr, *port, time.Duration(*timeout)*time.Second)
	proxy.Start()
}
