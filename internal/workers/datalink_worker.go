package workers

import (
	context "context"
	"log"
	"sync"

	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
	channels "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
	eth "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/ethernet"
)

type DataLinkWorker struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dlch  *channels.Channel[artifacts.CapturedFrame] // Channel for pulling capture frames.
	ntwch *channels.Channel[artifacts.NetworkPacket] // Channel for transferring network layer packets to the network workers.

	ethernetParser *eth.EthernetParser // Ethernet parser for parsing the captured frames.
}

func NewDataLinkWorker(dlch *channels.Channel[artifacts.CapturedFrame], ntwch *channels.Channel[artifacts.NetworkPacket]) *DataLinkWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &DataLinkWorker{
		dlch:   dlch,
		ntwch:  ntwch,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Rum method will start the worker, which continuously
// reads from the capture channel, parses the frames,
// and sends the parsed packets to the network channel.
func (dlw *DataLinkWorker) Run() {
	// Start the worker in a separate goroutine.
	dlw.wg.Add(1)
	go dlw.worker()
}

func (dlw *DataLinkWorker) worker() {
	defer dlw.wg.Done() // Mark the worker as done when it exits.
	// Run forever until the worker is stopped.
	for {
		// Read from the capture channel.
		captureFrame, ok := dlw.dlch.Pop(dlw.ctx)
		if !ok {
			// Channel is closed, stop the worker.
			log.Println("Network channel closed, stopping worker.")
			return
		}

		// Parse the frame and send the parsed packet to the network channel.
		packet, ed, err := dlw.ethernetParser.Parse(captureFrame.FrameData)
		if err != nil {
			// ToDo: Add error handling
			continue
		}

		if ed.EtherType != uint16(0x0800) {
			log.Printf("Non-IPv4 packet received, EtherType: %x. Skipping.", ed.EtherType)
			continue // Skip non-IPv4 packets for now. ToDo: Add support for other protocols.
		}

		// Create a NetworkPacket structure to send to the network channel.
		networkPacket := artifacts.NetworkPacket{
			PacketData: packet,
			// PacketLength: ,
			// PacketNumber: ,
		}

		log.Printf("Parsed network packet of length %d bytes", len(packet))
		ok = dlw.ntwch.Push(dlw.ctx, networkPacket)
		if !ok {
			// Channel is closed, stop the worker.
			log.Println("Network channel closed, stopping worker.")
			return
		}
		// }
	}
}

// Stop method will stop the worker, which will stop reading
// from the capture channel and stop sending packets to the network channel.
func (dlw *DataLinkWorker) Stop() {
	// Cancel the context to stop the worker.
	dlw.cancel()
	dlw.wg.Wait() // Wait for the worker to finish.
}
