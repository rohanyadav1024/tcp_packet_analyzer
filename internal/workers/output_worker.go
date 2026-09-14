package workers

import (
	context "context"
	"log"
	"sync"

	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
	channels "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
	output "github.com/rohanyadav1024/tcp_packet_analyzer/internal/output"
	store "github.com/rohanyadav1024/tcp_packet_analyzer/internal/store"
)

type OutputWorker struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	packetStore *store.PacketStore
	optch       *channels.Channel[artifacts.Message] // Channel for transferring transport layer packets to the transport workers.
	formatter   *output.Formatter
}

func NewOutputWorker(
	optch *channels.Channel[artifacts.Message],
	pktstr *store.PacketStore,
	formatter *output.Formatter) *OutputWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &OutputWorker{
		ctx:         ctx,
		cancel:      cancel,
		optch:       optch,
		packetStore: pktstr,
		formatter:   formatter,
	}
}

// Run method will start the worker, which continuously
func (ow *OutputWorker) Run() {
	// Start the worker in a separate goroutine.
	ow.wg.Add(1)
	go ow.worker()
}

func (ow *OutputWorker) Stop() {
	// Cancel the context to stop the worker.
	ow.cancel()
	ow.wg.Wait() // Wait for the worker to finish.
}

func (ow *OutputWorker) worker() {
	defer ow.wg.Done() //

	for {
		msgPacket, ok := ow.optch.Pop(ow.ctx)
		if !ok {
			// Channel is closed, stop the worker.
			// log.Println("Network channel closed, stopping worker.")
			return
		}

		id := msgPacket.ID
		packetData, ok := ow.packetStore.Get(id)
		if !ok {
			// Data is absent
			continue
		}

		log.Print("Packet recieved for printing")
		ow.formatter.PrintPacket(packetData)
	}
}
