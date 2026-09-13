package ipv4

const (
	// IPv4 header offsets
	versionIHLOffset     = 0
	tosOffset            = 1
	totalLengthOffset    = 2
	identificationOffset = 4
	flagsFragmentOffset  = 6
	ttlOffset            = 8
	protocolOffset       = 9
	headerChecksumOffset = 10
	sourceIPOffset       = 12
	destinationIPOffset  = 16

		// Constraints
	minimumIPv4HeaderLength = 20
	maximumIPv4HeaderLength = 60
)

type IPV4Data struct {
	Version        uint8
	IHL            uint8 // Internet Header Length (IHL) in 32-bit (4 bytes) words
	TOS            uint8
	TotalLength    uint16 // in bytes, includes header and data
	Identification uint16
	FlagsFragment  uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SourceIP       string
	DestinationIP  string
}