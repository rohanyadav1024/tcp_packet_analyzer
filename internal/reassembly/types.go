package reassembly

type PacketState uint8
type EventType uint8
type SystemCallType uint8

type MessageType uint8

type Message struct {
	Type    MessageType
	Body interface{}
}

type Packet struct {
	State   PacketState
	Payload interface{}
}

type Event struct {
	Type EventType
	AssemblyLineKey AssemblyLineKey
}

type SystemCall struct {
	Type SystemCallType
}

const (
	// PacketState values
	PacketStateReceived PacketState = iota
	PacketStateIngested
	PacketStateValidated

	// EventType values
	EventTypeCheckForCompletion EventType = iota
	EventTypeTimeout

	// SystemCallType values
	SystemCallShutdown SystemCallType = iota

	// MessageType values
	MessageTypePacket MessageType = iota
	MessageTypeEvent
	MessageTypeSystemCall
)

// ----------------------Assembly Line and Fragment Structures----------------------

type AssemblyLineKey struct {
	SourceIP       [4]byte
	DestinationIP  [4]byte
	Protocol       uint8
	Identification uint16
}

type ByteRange struct {
	Start uint16 // Start offset of the byte range
	End   uint16 // End offset of the byte range
}

type AssemblyLineState uint8

const (
	StateCollecting        AssemblyLineState = iota // 0: Not started
	StateCheckPending                               // 1: check pending
	StateWaitingForMissing                          // 2: waiting for missing
	StateCompleted                                  // 3: Completed
	StateDiscarded                                  // 4: Discarded
)



type AssemblyPacketRequest struct {
	AssemblyLineKey AssemblyLineKey
	FragmentOffset  uint16
	MoreFragments   bool
	Payload         []byte
}

type CompletionResult struct {
	IsComplete bool   // Indicates if the assembly line has received all expected fragments
}