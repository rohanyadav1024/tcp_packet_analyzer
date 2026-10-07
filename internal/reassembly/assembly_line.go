package reassembly

import "time"

type Assembly_Line struct {
	// Add fields and methods for managing reassembly of packets
	key           AssemblyLineKey   // Unique key for the assembly line based on source, destination, protocol, and identification
	state         AssemblyLineState // Current state of the assembly line
	createdAt     time.Time         // Timestamp of when the assembly line was created
	lastUpdatedAt time.Time         // Timestamp of the last update to the assembly line

	expectedPayloadLength  uint16 // Expected length of the payload for reassembly
	receivedFragmentsCount uint16 // Count of received fragments for this assembly line
	receivedUniqueBytes    uint16 // Count of unique bytes received for this assembly line

	fragments []fragment // Sorted Slice to hold the received exact fragments for this assembly line

	coverage []ByteRange // Slice to hold the coverage of received fragments for this assembly line
}

// NewAssemblyLine creates a new Assembly_Line instance with the provided key and expected payload length.
func NewAssemblyLine(key AssemblyLineKey, expectedPayloadLength uint16) *Assembly_Line {
	return &Assembly_Line{
		key:                   key,
		state:                 StateCollecting,
		createdAt:             time.Now(),
		lastUpdatedAt:         time.Now(),
		expectedPayloadLength: expectedPayloadLength,
		fragments:             []fragment{},
		coverage:              []ByteRange{},
	}
}

func (al *Assembly_Line) Ingest(key AssemblyLineKey, fragment fragment) bool {
	return true
}

func (al *Assembly_Line) CheckCompletion(key AssemblyLineKey) CompletionResult {
	return CompletionResult{}
}

func (al *Assembly_Line) Flatten(key AssemblyLineKey) ([]byte, error) {
	return nil, nil
}

func (al *Assembly_Line) Discard(key AssemblyLineKey) {}

func (al *Assembly_Line) FragmentCount(key AssemblyLineKey) uint16 {
	return 0
}

func (al *Assembly_Line) IsComplete(key AssemblyLineKey) bool {
	return false
}
