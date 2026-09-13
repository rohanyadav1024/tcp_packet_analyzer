package artifacts

type Warning struct {
	Layer   string // SEGMENT, PACKET, FRAME
	Type    string // TRUNCATED, MALFORMED, INCONSISTENT, UNSUPPORTED
	Message string
}
