package workers

import (
	context "context"
	"log"
	"sync"

	// "log"

	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
	channels "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
	tcp "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/tcp"
	store "github.com/rohanyadav1024/tcp_packet_analyzer/internal/store"
)

type TransportWorker struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	tpch        *channels.Channel[artifacts.TransportPacket] // Channel for transferring transport layer packets to the transport workers.
	tcpParser   *tcp.TCPParser                               // TCP parser for parsing the transport layer packets.
	packetStore *store.PacketStore
}

func NewTransportWorker(tpch *channels.Channel[artifacts.TransportPacket], tcpParser *tcp.TCPParser, pktstr *store.PacketStore) *TransportWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &TransportWorker{
		tpch:        tpch,
		tcpParser:   tcpParser,
		ctx:         ctx,
		cancel:      cancel,
		packetStore: pktstr,
	}
}

// Run method will start the worker, which continuously
// reads from the network channel, parses the packets,
// and sends the parsed packets to the transport channel.
func (tw *TransportWorker) Run() {
	// Start the worker in a separate goroutine.
	tw.wg.Add(1)
	go tw.worker()
}

func (tw *TransportWorker) Stop() {
	// Cancel the context to stop the worker.
	tw.cancel()
	tw.wg.Wait() // Wait for the worker to finish.
}

func (tw *TransportWorker) worker() {
	defer tw.wg.Done() // Mark the worker as done when it exits.
	// Run forever until the worker is stopped.
	for {
		transportPacket, ok := tw.tpch.Pop(tw.ctx)
		if !ok {
			// Channel is closed, stop the worker.
			log.Println("Transport channel closed, stopping worker.")
			return
		}

		pckd, err := tw.tcpParser.Parse(transportPacket.PacketData)

		log.Printf("Parsed Payload of length %d bytes", len(pckd.Payload))

		// Push data to store
		id := transportPacket.ID
		tw.packetStore.AddTCPData(id, &pckd)
		if err != nil {
		}
	}
}
