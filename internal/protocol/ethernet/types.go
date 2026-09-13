package ethernet

const (
	// Ethernet header offsets
	destMacOffset        = 0
	sourceMacOffset      = 6
	etherTypeOffset      = 12
	ethernetHeaderLength = 14
)

type EthernetData struct {
	DestinationMAC []byte
	SourceMAC      []byte
	EtherType      uint16
}