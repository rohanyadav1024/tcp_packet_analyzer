package reassembly

import (
	"context"
	"fmt"
	"sync"
)

type ReassemblyWorker struct {
	// Add fields for managing the reassembly worker
	ctx     context.Context    // Context for managing the lifecycle of the worker
	cancel  context.CancelFunc // Function to cancel the worker's context
	wg      sync.WaitGroup     // WaitGroup to manage the worker's goroutines
	runOnce sync.Once

	pool        *MessageQueue                     // Channel for receiving messages to process
	assemblyMap map[AssemblyLineKey]*AssemblyLine // Map to hold the assembly lines for reassembly

	pushOutput  PushToChannelCallback
	discardJunk PushToChannelCallback
}

func NewReassemblyWorker(
	pool *MessageQueue,
	pushOutput PushToChannelCallback,
	discardJunk PushToChannelCallback) *ReassemblyWorker {

	ctx, cancel := context.WithCancel(context.Background())
	return &ReassemblyWorker{
		ctx:         ctx,
		cancel:      cancel,
		pool:        pool,
		pushOutput:  pushOutput,
		discardJunk: discardJunk,
	}
}

// Run starts the reassembly worker, which listens for incoming messages and processes them.
func (w *ReassemblyWorker) Run() {
	w.runOnce.Do(func() {
		// Implementation for starting the reassembly worker
		w.wg.Add(1)
		go w.worker()
	})
}

// Stop stops the reassembly worker gracefully.
func (w *ReassemblyWorker) Stop() {
	// Implementation for stopping the reassembly worker
	w.cancel()
	w.wg.Wait()
}

func (w *ReassemblyWorker) worker() {
	defer w.wg.Done()

	for {
		// Extract Message from assigned pool and process
		msg := w.pool.Dequeue(w.ctx)
		switch msg.Type {
		case MessageTypeSystemCall:
			return

		case MessageTypeEvent:
			w.handleEvent(msg.Body.(Event))
			//

		case MessageTypePacket:
			w.handlePacket(msg.Body.(AssemblyPacketRequest))
		}
	}
}

func (w *ReassemblyWorker) handleEvent(event Event) {
	key := event.AssemblyLineKey

	switch event.Type {
	case EventTypeCheckForCompletion:
		al, exists := w.assemblyMap[key]
		if !exists {
			return
		}
		// Iscomplete
		if !al.IsComplete() {
			return
		}

		// Flatten, already completed
		payload, ok := al.Flatten()

		// Remove key from Map. No more processing on this line
		delete(w.assemblyMap, key)
		if !ok {
			return
		}

		// Push To Output for transport layer handling
		w.pushOutput(w.ctx, payload)
		fmt.Print("Packet pushed to Transport layer by Reassembly")

	case EventTypeTimeout:
		// Discard
		discardLine(key)
		delete(w.assemblyMap, key)
	}
}

func (w *ReassemblyWorker) handlePacket(req AssemblyPacketRequest) {
	key := req.AssemblyLineKey
	fragment := fragment{
		startOffset: req.StartOffset,
		endOffset:   req.EndOffset,
		dfBit:       req.DontFragment,
		mfBit:       req.MoreFragments,
		payload:     req.Payload,
	}

	// Fragment Validation
	if !fragment.Validate() {
		return //Just drop or even discard the line??
	}

	al, exists := w.assemblyMap[key]
	if !exists {
		// Create a new assembly line
		al = NewAssemblyLine(key)
		w.assemblyMap[key] = al

	}
	// Assembly Line for key is present
	// Process based on state of assembly line state and fragment

	// Ingestion
	ok := al.Ingest(fragment, fragment.mfBit)
	if !ok {
		if al.state == StateDiscarded {
			// Remove the line
			discardLine(al.key)
			delete(w.assemblyMap, key)
		}
		// Duplicate case do nothing
		return
	}

	// Add associated packet store's packet Id for resemblence later
	al.packetIds = append(al.packetIds, fragment.packetId)

	// Fragment can be last in line -> Probability of completion
	// Waiting for missing fragment -> Probability of completion
	if fragment.IsLast() || al.state == StateWaitingForMissing {
		// Create event in pool for checkingCompletion
		w.pool.Enqueue(w.ctx, createEvent(al.key, EventTypeCheckForCompletion))
		return
	}
}

func discardLine(assemblyLineKey AssemblyLineKey) {
	panic("unimplemented")
}

func createEvent(key AssemblyLineKey, etyp EventType) Message {
	return Message{
		Type: MessageTypeEvent,
		Body: Event{
			Type:            etyp,
			AssemblyLineKey: key,
		},
	}
}

//Workflow lifecycle

// 1st Fragment of packet arrives
//		Msg type = packet
// 		Validate(fragment) Always do validation first
// 		no Assembly Line found -> Create assembly line (default state = collecting)
//		Ingest(fragment)
//		Check if it's last
// 			True -> finalFragmentReceived = true + state = CheckPending + CreateEvent(Key, CheckForCompletion)
// 			False -> continue other messages
//
// More Fragment of packet arrives
//		Msg type = packet
// 		Validate(fragment) Always do validation first
// 		Get assembly line
//		Ingest(fragment)
//		Check if it's last
// 			True -> finalFragmentReceived = true + state = CheckPending + CreateEvent(Key, CheckForCompletion)
// 			False -> continue other messages
//
// Last Fragment arrived (Can be at any offset not necessarily at end)
//		Msg type = packet
// 		Validate(fragment) Always do validation first
// 		Get assembly line
//		Ingest(fragment)
//		Check if it's last
// 			True -> finalFragmentReceived = true + state = CheckPending + CreateEvent(Key, CheckForCompletion)
// 			False -> continue other messages
//
// Fragment arrived and state = WaitForMissing
// Once checkForCompletion done but IsComplete was False
//		Msg type = packet
// 		Validate(fragment) Always do validation first
// 		Get assembly line
//		Ingest(fragment)
// 		check state == WaitingForMissing
// 			True -> IsComplete() -> CreateEvent(CheckForCompletion) + state = CheckPending else DoNothing
//
//
//
//
// Event Arrived
// 		Msg type = Event
// 		Get Event Type
// 			Timeout: Discard()
// 			CheckForCompletion:
// 				IsComplete():
// 				True -> state = Completed | Flatten() | al.pushOutput()
// 				False -> state = WaitForMissing {No event creation}
