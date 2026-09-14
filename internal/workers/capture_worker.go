package workers

import (
	context "context"
	// "log"
	"sync"
	"sync/atomic"

	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
	capture "github.com/rohanyadav1024/tcp_packet_analyzer/internal/capture"
	channels "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
)

type CaptureWorker struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	capture         *capture.Capture                           // Capture source for capturing frames.
	dataLinkChannel *channels.Channel[artifacts.CapturedFrame] // Channel for sending captured frames to the data link worker.

	nextID atomic.Uint64
}

func NewCaptureWorker(
	captureChannel *channels.Channel[artifacts.CapturedFrame],
	capture *capture.Capture) *CaptureWorker {

	ctx, cancel := context.WithCancel(context.Background())
	return &CaptureWorker{
		dataLinkChannel: captureChannel,
		capture:         capture,
		ctx:             ctx,
		cancel:          cancel,
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
		data, ci, err := cw.capture.ReadPacketData()
		if err != nil {
			// Handle error appropriately.
			continue
		}

		id := cw.nextID.Add(1)
		captureFrame := artifacts.CapturedFrame{
			ID:             id,
			FrameData:      data,
			TimeStamp:      ci.Timestamp,
			FrameLength:    ci.CaptureLength, //Actual captured length of frame,
			OriginalLength: ci.Length,        //Length before capturing
		}

		// Send the captured frame to the capture channel.
		// log.Printf("Captured frame of length %d bytes", captureLength)
		ok := cw.dataLinkChannel.Push(cw.ctx, captureFrame)
		if !ok {
			// Channel is closed, stop the worker.
			return
		}
		// }
	}
}
