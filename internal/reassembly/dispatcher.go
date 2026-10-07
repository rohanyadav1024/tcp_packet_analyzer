package reassembly

import (
	"context"
	"sync"

	"github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
)

type Dispatcher struct {
	// Add fields for managing the reassembly worker
	ctx    context.Context    // Context for managing the lifecycle of the worker
	cancel context.CancelFunc // Function to cancel the worker's context
	wg     sync.WaitGroup     // WaitGroup to manage the worker's goroutines

	pools []*MessageQueue // pools for pushing messages to the reassembly workers

	rlyc *channels.Channel[AssemblyPacketRequest]   // Channel for receiving packets from the network layer
}

func NewDispatcher(
	pools []*MessageQueue,
	rlyc *channels.Channel[AssemblyPacketRequest]) *Dispatcher {

	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{
		ctx:    ctx,
		cancel: cancel,
		pools:  pools,
		rlyc:   rlyc,
	}
}

// Run starts the reassembly worker, which listens for incoming messages and processes them.
func (w *Dispatcher) Run() {
	// Implementation for starting the reassembly worker
	w.wg.Add(1)
	go w.worker()
}

// Stop stops the reassembly worker gracefully.
func (w *Dispatcher) Stop() {
	// Implementation for stopping the reassembly worker
	w.cancel()
	w.wg.Wait()
}

func (w *Dispatcher) worker() {
	defer w.wg.Done() // Mark the worker as done when it exits.
	// Run forever until the worker is stopped.
	for {
		// Read from the reassembly channel and process the incoming messages.
	}
}