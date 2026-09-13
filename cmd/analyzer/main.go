package main

import (
	// "flag"
	"fmt"
	// "log"
	"os"
	"os/signal"
	"syscall"

	engine "github.com/rohanyadav1024/tcp_packet_analyzer/internal/engine"
)

func main() {
	// Parse command line arguments.
	// interfaceName := flag.String("i", "eth0", "Network interface to capture packets from")
	// flag.Parse()

	// Create a new engine.
	captureEngine := engine.NewEngine()

	// Start the engine.
	captureEngine.Start()

	// Wait for a termination signal (e.g., Ctrl+C).
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nTermination signal received. Stopping the engine...")

	// Stop the engine.
	captureEngine.Stop()
}