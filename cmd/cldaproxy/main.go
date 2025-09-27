package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/wfdewith/cldaproxy/internal/proxy"
)

func main() {
	port := flag.Int("port", 3890, "listen port")
	timeout := flag.Int("timeout", 5, "timeout in seconds for communicating with upstream")
	debug := flag.Bool("debug", false, "print debugging logs")
	flag.Parse()

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

	proxy := proxy.New(*port, time.Duration(*timeout)*time.Second)
	proxy.Start()
}
