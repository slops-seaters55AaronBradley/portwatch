package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/portwatch/portwatch/internal/config"
	"github.com/portwatch/portwatch/internal/monitor"
)

const version = "0.1.0"

func main() {
	// CLI flags
	configPath := flag.String("config", "portwatch.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	if *showVersion {
		fmt.Printf("portwatch v%s\n", version)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		cfg.Verbose = true
	}

	fmt.Printf("portwatch v%s starting — polling every %s\n", version, cfg.Interval)

	// Create and start the port monitor
	m, err := monitor.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing monitor: %v\n", err)
		os.Exit(1)
	}

	// Handle graceful shutdown on SIGINT / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		fmt.Printf("\nreceived signal %s, shutting down...\n", sig)
		m.Stop()
	}()

	// Run blocks until Stop() is called
	if err := m.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "monitor error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("portwatch stopped.")
}
