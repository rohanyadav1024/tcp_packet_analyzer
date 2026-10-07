package reassembly

import "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"

type ReassemblyManager struct {
	// Add fields for managing the reassembly process
	workerPoolSize        int // Number of workers in the reassembly worker pool
	messageQueueSize      int // Size of the message queue for distributing packets to workers
	reassemblyChannelSize int // Size of the reassembly channel for receiving packets from the network layer

	rsmblychannel *channels.Channel[AssemblyPacketRequest] // Channel for receiving packets from the network layer
	dispatcher    *Dispatcher                              // Single Dispatcher for managing the reassembly workers

	workerPool       []*ReassemblyWorker // Slice of reassembly workers
	messageQueuePool []*MessageQueue     // Slice of message queues for distributing packets to workers

	packetOutput  PushToChannelCallback
	packetDiscard PushToChannelCallback
}

func (manager *ReassemblyManager) loadConfig() {
	// Load configuration values for the reassembly manager
	manager.workerPoolSize = 4         // Example: Number of workers in the pool
	manager.messageQueueSize = 100     // Example: Size of the message queue
	manager.reassemblyChannelSize = 50 // Example: Size of the reassembly channel
}

func NewReassemblyManager(packetOutput PushToChannelCallback, packetDiscard PushToChannelCallback) *ReassemblyManager {
	// Create a new ReassemblyManager instance.
	manager := &ReassemblyManager{
		packetOutput:  packetOutput,
		packetDiscard: packetDiscard,
	}

	manager.loadConfig()
	// Initialize the worker pool and message queue pool.
	manager.workerPool = make([]*ReassemblyWorker, manager.workerPoolSize)
	manager.messageQueuePool = make([]*MessageQueue, manager.workerPoolSize)

	for i := range manager.workerPoolSize {
		manager.messageQueuePool[i] = NewMessageQueue(manager.messageQueueSize)
		manager.workerPool[i] = NewReassemblyWorker(manager.messageQueuePool[i])
	}

	manager.rsmblychannel = channels.NewChannel[AssemblyPacketRequest](manager.reassemblyChannelSize)
	manager.dispatcher = NewDispatcher(manager.messageQueuePool, manager.rsmblychannel) // Pass the message queue pool to the dispatcher

	return manager
}

func (manager *ReassemblyManager) Start() {
	// Start the dispatcher and all reassembly workers.
	manager.dispatcher.Run()
	for _, worker := range manager.workerPool {
		worker.Run()
	}
}

func (manager *ReassemblyManager) Stop() {
	// Stop the dispatcher and all reassembly workers.
	manager.dispatcher.Stop()
	for _, worker := range manager.workerPool {
		worker.Stop()
	}
}
