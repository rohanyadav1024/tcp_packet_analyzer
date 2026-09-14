package store

import (
	"fmt"
	"os"
	"sync"
	"time"

	eth "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/ethernet"
	ipv4 "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/ipv4"
	tcp "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/tcp"
)

// PacketData represents the data structure for storing packet information in the database.
type PacketStore struct {
	packets map[uint64]*PacketData // Map to store packet data with unique IDs.
	mu      sync.RWMutex           // Mutex to ensure thread-safe access to the packets map.
}

func NewPacketStore() *PacketStore {
	return &PacketStore{
		packets: make(map[uint64]*PacketData),
	}
}

// Internal helper
func (ps *PacketStore) getOrCreateLocked(id uint64) *PacketData {
	packet, exists := ps.packets[id]
	if !exists {
		packet = &PacketData{ID: id}
		ps.packets[id] = packet
	}

	return packet
}

// GetOrCreate retrieves a packet from the store by its ID.
// If the packet does not exist, it creates a new one and adds it to the store.
func (ps *PacketStore) GetOrCreate(id uint64) *PacketData {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	return ps.getOrCreateLocked(id)
}

func (ps *PacketStore) Get(id uint64) (*PacketData, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	packet, exists := ps.packets[id]
	return packet, exists
}

func (ps *PacketStore) Delete(id uint64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.packets, id)
}

func (ps *PacketStore) AddEthernetData(id uint64, data *eth.EthernetData) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	packet := ps.getOrCreateLocked(id)
	packet.Ethernet = data
}

func (ps *PacketStore) AddIPV4Data(id uint64, data *ipv4.IPV4Data) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	packet := ps.getOrCreateLocked(id)
	packet.IPv4 = data
}

func (ps *PacketStore) AddTCPData(id uint64, data *tcp.TCPData) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	packet := ps.getOrCreateLocked(id)
	packet.TCP = data
}

func (ps *PacketStore) AddCaptureMetadata(
	id uint64,
	timestamp time.Time,
	capturedLength int,
	originalLength int,
) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	packet := ps.getOrCreateLocked(id)

	packet.Timestamp = timestamp
	packet.CapturedLength = capturedLength
	packet.OriginalLength = originalLength
}

// Temparory method
func (ps *PacketStore) DumpToFile(filename string) error {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for id, packet := range ps.packets {
		fmt.Fprintf(file, "========================================\n")
		fmt.Fprintf(file, "Packet ID: %d\n", id)
		fmt.Fprintf(file, "========================================\n\n")

		fmt.Fprintf(file, "Packet Data:\n")
		fmt.Fprintf(file, "%+v\n\n", *packet)

		if packet.Ethernet != nil {
			fmt.Fprintf(file, "Ethernet:\n")
			fmt.Fprintf(file, "%+v\n\n", *packet.Ethernet)
		}

		if packet.IPv4 != nil {
			fmt.Fprintf(file, "IPv4:\n")
			fmt.Fprintf(file, "%+v\n\n", *packet.IPv4)
		}

		if packet.TCP != nil {
			fmt.Fprintf(file, "TCP:\n")
			fmt.Fprintf(file, "%+v\n\n", *packet.TCP)
		}

		fmt.Fprintf(file, "\n")
	}

	return nil
}
