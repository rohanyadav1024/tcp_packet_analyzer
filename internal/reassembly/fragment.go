package reassembly

const maxIPv4PayloadSize = 65515

type fragment struct {
	packetId uint64 //packet Id of associated packet in packet store

	startOffset uint16 // Offset of the fragment in the original packet
	endOffset   uint16 // End offset of the fragment in the original packet
	payload     []byte // Actual data of the fragment

	mfBit bool // More Fragments bit indicating if there are more fragments to follow
	dfBit bool // Don't Fragment bit indicating if the packet should not be fragmented
}

func (f *fragment) Validate() bool {
	if f == nil {
		return false
	}

	// The end offset must not precede the start offset.
	if f.endOffset < f.startOffset {
		return false
	}

	// A fragment submitted for reassembly must contain data.
	if len(f.payload) == 0 {
		return false
	}

	// The byte range must match the actual payload length.
	if int(f.endOffset-f.startOffset) != len(f.payload) {
		return false
	}

	// The start offset must be aligned to 8 bytes.
	if f.startOffset%8 != 0 {
		return false
	}

	// Non-final fragments must have payload lengths
	// divisible by 8 bytes.
	if f.mfBit && len(f.payload)%8 != 0 {
		return false
	}

	// DF and fragmentation are mutually exclusive.
	if f.dfBit {
		return false
	}

	// The reassembled IPv4 payload cannot exceed the
	// maximum permitted by the IPv4 total-length field.
	if f.endOffset > maxIPv4PayloadSize {
		return false
	}

	// Offset zero with MF unset represents an
	// unfragmented packet, not a fragment to reassemble.
	if f.startOffset == 0 && !f.mfBit {
		return false
	}

	return true
}

func (f *fragment) PayloadLength() uint16 {
	return uint16(len(f.payload))
}

func (f *fragment) IsFirst() bool {
	return f.startOffset == 0
}

func (f *fragment) IsLast() bool {
	if f.mfBit {
		return false
	}
	return true
}
