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

// PacketStore stores captured packets and reassembled datagrams separately.
type PacketStore struct {
	packets   map[uint64]*PacketData
	datagrams map[uint64]*ReassembledDatagram

	mu sync.RWMutex
}

func NewPacketStore() *PacketStore {
	return &PacketStore{
		packets:   make(map[uint64]*PacketData),
		datagrams: make(map[uint64]*ReassembledDatagram),
	}
}

// ---- Captured packet methods ----

// getOrCreatePacketLocked must only be called while holding the write lock.
func (ps *PacketStore) getOrCreatePacketLocked(id uint64) *PacketData {
	packet, exists := ps.packets[id]
	if !exists {
		packet = &PacketData{ID: id}
		ps.packets[id] = packet
	}

	return packet
}

func (ps *PacketStore) GetOrCreatePacket(id uint64) *PacketData {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	return ps.getOrCreatePacketLocked(id)
}

func (ps *PacketStore) GetPacket(id uint64) (*PacketData, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	packet, exists := ps.packets[id]
	return packet, exists
}

func (ps *PacketStore) DeletePacket(id uint64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	delete(ps.packets, id)
}

func (ps *PacketStore) AddEthernetData(id uint64, data *eth.EthernetData) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.getOrCreatePacketLocked(id).Ethernet = data
}

func (ps *PacketStore) AddIPV4Data(id uint64, data *ipv4.IPV4Data) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.getOrCreatePacketLocked(id).IPv4 = data
}

func (ps *PacketStore) AddTCPData(id uint64, data *tcp.TCPData) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.getOrCreatePacketLocked(id).TCP = data
}

func (ps *PacketStore) AddCaptureMetadata(
	id uint64,
	timestamp time.Time,
	capturedLength int,
	originalLength int,
) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	packet := ps.getOrCreatePacketLocked(id)
	packet.Timestamp = timestamp
	packet.CapturedLength = capturedLength
	packet.OriginalLength = originalLength
}

func (ps *PacketStore) AddPacketWarning(id uint64, warning string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	packet := ps.getOrCreatePacketLocked(id)
	packet.Warnings = append(packet.Warnings, warning)
}

// ---- Reassembled datagram methods ----

// getOrCreateDatagramLocked must only be called while holding the write lock.
func (ps *PacketStore) getOrCreateDatagramLocked(
	id uint64,
) *ReassembledDatagram {
	datagram, exists := ps.datagrams[id]
	if !exists {
		datagram = &ReassembledDatagram{ID: id}
		ps.datagrams[id] = datagram
	}

	return datagram
}

// AddDatagram stores a newly constructed reassembled datagram.
// The slices are copied so the caller can safely reuse its input buffers.
func (ps *PacketStore) AddDatagram(data *ReassembledDatagram) {
	if data == nil {
		return
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	datagram := *data
	datagram.FragmentPacketIDs = append(
		[]uint64(nil), data.FragmentPacketIDs...,
	)
	datagram.Payload = append([]byte(nil), data.Payload...)

	ps.datagrams[data.ID] = &datagram
}

func (ps *PacketStore) GetOrCreateDatagram(
	id uint64,
) *ReassembledDatagram {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	return ps.getOrCreateDatagramLocked(id)
}

func (ps *PacketStore) GetDatagram(
	id uint64,
) (*ReassembledDatagram, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	datagram, exists := ps.datagrams[id]
	return datagram, exists
}

func (ps *PacketStore) DeleteDatagram(id uint64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	delete(ps.datagrams, id)
}

func (ps *PacketStore) AddDatagramTCPData(
	id uint64,
	data *tcp.TCPData,
) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.getOrCreateDatagramLocked(id).TCP = data
}

// ---- Temporary debugging method ----

func (ps *PacketStore) DumpToFile(filename string) error {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for id, packet := range ps.packets {
		fmt.Fprintln(file, "========================================")
		fmt.Fprintf(file, "Packet ID: %d\n", id)
		fmt.Fprintln(file, "========================================")
		fmt.Fprintf(file, "Packet Data:\n%+v\n\n", *packet)

		if packet.Ethernet != nil {
			fmt.Fprintf(file, "Ethernet:\n%+v\n\n", *packet.Ethernet)
		}
		if packet.IPv4 != nil {
			fmt.Fprintf(file, "IPv4:\n%+v\n\n", *packet.IPv4)
		}
		if packet.TCP != nil {
			fmt.Fprintf(file, "TCP:\n%+v\n\n", *packet.TCP)
		}
	}

	for id, datagram := range ps.datagrams {
		fmt.Fprintln(file, "========================================")
		fmt.Fprintf(file, "Reassembled Datagram ID: %d\n", id)
		fmt.Fprintln(file, "========================================")
		fmt.Fprintf(file, "Datagram Data:\n%+v\n\n", *datagram)
	}

	return nil
}
