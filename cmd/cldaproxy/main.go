package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/wfdewith/cldaproxy/internal/proxy"
)

func main() {
	ip := flag.String("ip", "127.0.0.1", "listen IP")
	port := flag.Int("port", 3890, "listen port")
	timeout := flag.Int("timeout", 5, "timeout in seconds for communicating with upstream")
	debug := flag.Bool("debug", false, "print debugging logs")
	flag.Parse()

	ipaddr := net.ParseIP(*ip)
	if ipaddr == nil {
		fmt.Fprintf(os.Stderr, "invalid IP address: %q\n", *ip)
		os.Exit(1)
	}

	if *port < 1 || *port > 65535 {
		fmt.Fprintf(os.Stderr, "port must be in range 1-65535, got %d\n", *port)
		os.Exit(1)
	}

	if *timeout < 0 {
		fmt.Fprintf(os.Stderr, "timeout must be greater than 0, got %d\n", *timeout)
		os.Exit(1)
	}

	logLevel := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	if *debug {
		logLevel.Set(slog.LevelDebug)
	}

	proxy := proxy.New(ipaddr, *port, time.Duration(*timeout)*time.Second)
	proxy.Start()
}
