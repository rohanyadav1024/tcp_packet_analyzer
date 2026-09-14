package workers

import (
	context "context"
	"log"
	"sync"

	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
	capture "github.com/rohanyadav1024/tcp_packet_analyzer/internal/capture"
	channels "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
)

type CaptureWorker struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	capture        *capture.Capture                           // Capture source for capturing frames.
	captureChannel *channels.Channel[artifacts.CapturedFrame] // Channel for sending captured frames to the data link worker.
}

func NewCaptureWorker(
	captureChannel *channels.Channel[artifacts.CapturedFrame],
	capture *capture.Capture) *CaptureWorker {

	ctx, cancel := context.WithCancel(context.Background())
	return &CaptureWorker{
		captureChannel: captureChannel,
		capture:        capture,
		ctx:            ctx,
		cancel:         cancel,
	}
}

func (cw *CaptureWorker) Run() {
	// Start the worker in a separate goroutine.
	cw.wg.Add(1)
	go cw.worker()
}

func (cw *CaptureWorker) Stop() {
	// Cancel the context to stop the worker.
	cw.cancel()
	// cw.capture.Close() // Close the capture source to stop capturing frames.
	cw.wg.Wait() // Wait for the worker to finish.
}

func (cw *CaptureWorker) worker() {
	defer cw.wg.Done() // Mark the worker as done when it exits.
	// Run forever until the worker is stopped.
	for {
		// Capture a frame and send it to the capture channel.
		data, _, captureLength, err := cw.capture.ReadPacketData()
		if err != nil {
			// Handle error appropriately.
			continue
		}
		captureFrame := artifacts.CapturedFrame{
			FrameData:   data,
			FrameLength: captureLength,
		}

		// Send the captured frame to the capture channel.
		log.Printf("Captured frame of length %d bytes", captureLength)
		ok := cw.captureChannel.Push(cw.ctx, captureFrame)
		if !ok {
			// Channel is closed, stop the worker.
			return
		}
		// }
	}
}
