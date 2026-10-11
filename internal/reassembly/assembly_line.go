package reassembly

import (
	"bytes"
	"sort"
	"time"
)

type AssemblyLine struct {
	// Add fields and methods for managing reassembly of packets
	key           AssemblyLineKey   // Unique key for the assembly line based on source, destination, protocol, and identification
	state         AssemblyLineState // Current state of the assembly line
	createdAt     time.Time         // Timestamp of when the assembly line was created
	lastUpdatedAt time.Time         // Timestamp of the last update to the assembly line

	finalFragmentReceived bool

	expectedPayloadLength  uint16 // Expected length of the payload for reassembly
	receivedFragmentsCount uint16 // Count of received fragments for this assembly line
	receivedUniqueBytes    uint16 // Count of unique bytes received for this assembly line

	packetIds []uint64   //Keep track of associated packets in packet store
	fragments []fragment // Sorted Slice to hold the received exact fragments for this assembly line

	coverage []ByteRange // Slice to hold the coverage of received fragments for this assembly line
	gaps     []ByteRange
}

// NewAssemblyLine creates a new AssemblyLine instance with the provided key and expected payload length.
func NewAssemblyLine(key AssemblyLineKey) *AssemblyLine {
	now := time.Now()

	return &AssemblyLine{
		key:           key,
		state:         StateCollecting,
		createdAt:     now,
		lastUpdatedAt: now,
	}
}

// Output -> Ingested | Duplicate Not ingested | Conflict Not ingested
func (al *AssemblyLine) Ingest(fragment fragment, moreFrags bool) bool {

	fragments := al.fragments
	s, e := fragment.startOffset, fragment.endOffset
	cover := al.coverage
	index := indexOfFragment(fragments, s, e)

	if !hasOverlap(fragments, s, e) {
		return al.insertFragment(fragment, index, moreFrags)
	}

	if hasConflict(fragments, s, e, fragment.payload) {
		// Conflict detected, discard the fragment
		al.state = StateDiscarded //Implement in worker to discard this
		return false
	}

	if !hasNewBytes(cover, s, e) {
		// Duplicate incoming, drop the packet
		return false
	}

	// New bytes with overlap: Insertion
	return al.insertFragment(fragment, index, moreFrags)
}

func (al *AssemblyLine) Flatten() ([]byte, bool) {
	if al.state != StateCompleted {
		return nil, false //Incomplete assembly
	}

	if al.expectedPayloadLength == 0 {
		return nil, false
	}

	if len(al.gaps) != 0 {
		return nil, false
	}

	payload := make([]byte, al.expectedPayloadLength)
	// Create payload from all the fragments
	for _, f := range al.fragments {
		s, e := f.startOffset, f.endOffset

		if s < 0 || e > al.expectedPayloadLength || e-s != uint16(f.PayloadLength()) {
			return nil, false
		}

		copy(payload[int(s):int(e)], f.payload)
	}

	return payload, true
}

func (al *AssemblyLine) Discard() {
	if al.state == StateDiscarded {
		return
	}

	al.state = StateDiscarded

	// Release references to fragment payloads and backing arrays.
	al.fragments = nil
	al.coverage = nil
	al.gaps = nil

	al.receivedFragmentsCount = 0
	al.receivedUniqueBytes = 0
}

func (al *AssemblyLine) FragmentCount() uint16 {
	return uint16(len(al.fragments))
}

func (al *AssemblyLine) IsComplete() bool {
	// Terminal states must not transition again.
	if al.state == StateCompleted ||
		al.state == StateDiscarded {
		return al.state == StateCompleted
	}

	if !al.finalFragmentReceived {
		// Still collecting, Keep state as it is
		return false
	}

	if len(al.fragments) == 0 {
		return false
	}

	span := al.expectedPayloadLength

	isComplete := al.receivedUniqueBytes == span && len(al.gaps) == 0
	if isComplete {
		al.state = StateCompleted
	} else {
		// Final Fragment recieved -> Could be Waiting for Missing
		al.state = StateWaitingForMissing
	}

	return isComplete
}

// Helper functions
func indexOfFragment(fs []fragment, s uint16, e uint16) int {
	// Index with binary search
	return sort.Search(len(fs), func(i int) bool {
		if s != fs[i].startOffset {
			return s < fs[i].startOffset
		}
		return e <= fs[i].endOffset
	})
}

func hasOverlap(fs []fragment, s uint16, e uint16) bool {
	for _, f := range fs {
		if s < f.endOffset && e > f.startOffset {
			return true
			// Cover every case of overlapping with existing fragment
		}
	}
	return false
}

func hasNewBytes(cover []ByteRange, s, e uint16) bool {
	if s >= e {
		return false
	}

	for _, r := range cover {
		if r.Start <= s && r.End >= e {
			return false
		}
	}

	return true
}

func hasConflict(fs []fragment, s uint16, e uint16, incomingBytes []byte) bool {
	for _, f := range fs {
		if s >= f.endOffset || e <= f.startOffset {
			continue //no overlap detect
		}

		overlapStart := max(s, f.startOffset)     //universal byte marker for overlapping start
		overlapEnd := min(e, f.endOffset)         //universal byte marker for overlapping end
		overlapBytes := overlapEnd - overlapStart //exact number of bytes overlapped

		existingIndex := overlapStart - f.startOffset //starting byte index of existing fragment 0 to len(fragment)
		incomingIndex := overlapStart - s             //starting byte index of incoming fragment 0 to len(fragment)

		existOverlapFrag := f.payload[existingIndex : existingIndex+overlapBytes]
		incomOverlapFrag := incomingBytes[incomingIndex : incomingIndex+overlapBytes]

		if !bytes.Equal(existOverlapFrag, incomOverlapFrag) {
			return true
		}
	}
	return false
}

func (al *AssemblyLine) insertFragment(ifrag fragment, index int, moreFrags bool) bool {
	// 1. Validate insertion index.
	if index < 0 || index > len(al.fragments) {
		return false
	}

	// 2. Insert fragment in sorted order.
	al.fragments = append(al.fragments, fragment{})
	copy(al.fragments[index+1:], al.fragments[index:])
	al.fragments[index] = ifrag

	// A fragment with MF = 0 establishes the payload's end.
	if !moreFrags {
		// Check if already a final fragment arrived and current one conflicting
		if al.finalFragmentReceived && al.expectedPayloadLength != ifrag.endOffset {
			// Discard the Line
			al.state = StateDiscarded
			return false
		}
		al.expectedPayloadLength = ifrag.endOffset
		al.finalFragmentReceived = true
	}

	// 3. Update coverage using the fragment's byte range.
	incoming := ByteRange{
		Start: ifrag.startOffset,
		End:   ifrag.endOffset, // Exclusive
	}

	al.insertAndMergeCoverage(incoming)

	// 4. Recalculate the number of uniquely covered bytes.
	var uniqueBytes uint32
	for _, r := range al.coverage {
		uniqueBytes += uint32(r.End - r.Start)
	}
	al.receivedUniqueBytes = uint16(uniqueBytes)

	// 5. Recalculate missing byte ranges.
	al.updateGaps()

	// 6. Update fragment count and timestamp.
	al.receivedFragmentsCount++
	al.lastUpdatedAt = time.Now()

	return true
}

// insertAndMergeCoverage inserts the incoming range into sorted coverage
// and merges overlapping or adjacent ranges.
func (al *AssemblyLine) insertAndMergeCoverage(incoming ByteRange) {
	merged := make([]ByteRange, 0, len(al.coverage)+1)
	inserted := false

	for _, existing := range al.coverage {
		if existing.End < incoming.Start {
			// Existing range is strictly before incoming.
			merged = append(merged, existing)
			continue
		}

		if incoming.End < existing.Start {
			// Incoming belongs before this existing range.
			if !inserted {
				merged = append(merged, incoming)
				inserted = true
			}

			merged = append(merged, existing)
			continue
		}

		// Ranges overlap or are adjacent. Expand incoming.
		if existing.Start < incoming.Start {
			incoming.Start = existing.Start
		}

		if existing.End > incoming.End {
			incoming.End = existing.End
		}
	}

	if !inserted {
		merged = append(merged, incoming)
	}

	al.coverage = merged
}

// updateGaps recalculates all uncovered ranges within the expected payload.
func (al *AssemblyLine) updateGaps() {
	gaps := make([]ByteRange, 0)
	cursor := uint16(0)

	for _, r := range al.coverage {
		// Intermediatary gaps between fragments or at start of line
		if cursor < r.Start {
			gaps = append(gaps, ByteRange{
				Start: cursor,
				End:   r.Start,
			})
		}

		if r.End > cursor {
			cursor = r.End
		}
	}
	// Not recording the trailing gap
	al.gaps = gaps
}
