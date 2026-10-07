package reassembly

type fragment struct {
	startOffset uint16 // Offset of the fragment in the original packet
	endOffset   uint16 // End offset of the fragment in the original packet
	payload     []byte // Actual data of the fragment

	mfBit bool // More Fragments bit indicating if there are more fragments to follow
	dfBit bool // Don't Fragment bit indicating if the packet should not be fragmented
}

func (f *fragment) Validate() bool {
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