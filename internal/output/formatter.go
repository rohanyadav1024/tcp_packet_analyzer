package output

import (
	"fmt"
	"io"
	"net"

	"github.com/rohanyadav1024/tcp_packet_analyzer/internal/store"
)

type Formatter struct {
	writer io.Writer
}

func NewFormatter(writer io.Writer) *Formatter {
	return &Formatter{
		writer: writer,
	}
}

func (f *Formatter) PrintPacket(packet *store.PacketData) {
	if packet == nil {
		return
	}

	fmt.Fprintf(f.writer, "\n========================================\n")
	fmt.Fprintf(f.writer, "Packet #%d\n", packet.ID)
	fmt.Fprintf(f.writer, "========================================\n")

	f.printMetadata(packet)
	f.printEthernet(packet)
	f.printIPv4(packet)
	f.printTCP(packet)
	f.printWarnings(packet)

	fmt.Fprintln(f.writer)
}

func (f *Formatter) printMetadata(packet *store.PacketData) {
	fmt.Fprintln(f.writer, "\n[Packet]")

	fmt.Fprintf(f.writer, "  ID:              %d\n", packet.ID)
	fmt.Fprintf(f.writer, "  Timestamp:       %s\n", packet.Timestamp.Format("2006-01-02 15:04:05.000000"))
	fmt.Fprintf(f.writer, "  Captured Length:  %d bytes\n", packet.CapturedLength)
	fmt.Fprintf(f.writer, "  Original Length:  %d bytes\n", packet.OriginalLength)
}

func (f *Formatter) printEthernet(packet *store.PacketData) {
	if packet.Ethernet == nil {
		return
	}

	ethernet := packet.Ethernet

	fmt.Fprintln(f.writer, "\n[Ethernet II]")

	fmt.Fprintf(
		f.writer,
		"  Destination MAC: %s\n",
		formatMAC(ethernet.DestinationMAC),
	)

	fmt.Fprintf(
		f.writer,
		"  Source MAC:      %s\n",
		formatMAC(ethernet.SourceMAC),
	)

	fmt.Fprintf(
		f.writer,
		"  EtherType:       0x%04X\n",
		ethernet.EtherType,
	)
}

func (f *Formatter) printIPv4(packet *store.PacketData) {
	if packet.IPv4 == nil {
		return
	}

	ip := packet.IPv4

	fmt.Fprintln(f.writer, "\n[IPv4]")

	fmt.Fprintf(f.writer, "  Version:          %d\n", ip.Version)
	fmt.Fprintf(f.writer, "  IHL:              %d (%d bytes)\n", ip.IHL, int(ip.IHL)*4)
	fmt.Fprintf(f.writer, "  TOS:              0x%02X\n", ip.TOS)
	fmt.Fprintf(f.writer, "  Total Length:     %d bytes\n", ip.TotalLength)
	fmt.Fprintf(f.writer, "  Identification:   0x%04X\n", ip.Identification)
	fmt.Fprintf(f.writer, "  Flags/Fragment:   0x%04X\n", ip.FlagsFragment)
	fmt.Fprintf(f.writer, "  TTL:              %d\n", ip.TTL)
	fmt.Fprintf(f.writer, "  Protocol:         %d\n", ip.Protocol)
	fmt.Fprintf(f.writer, "  Header Checksum:  0x%04X\n", ip.HeaderChecksum)
	fmt.Fprintf(f.writer, "  Source IP:        %s\n", ip.SourceIP)
	fmt.Fprintf(f.writer, "  Destination IP:   %s\n", ip.DestinationIP)
}

func (f *Formatter) printTCP(packet *store.PacketData) {
	if packet.TCP == nil {
		return
	}

	tcp := packet.TCP

	fmt.Fprintln(f.writer, "\n[TCP]")

	fmt.Fprintf(f.writer, "  Source Port:      %d\n", tcp.SourcePort)
	fmt.Fprintf(f.writer, "  Destination Port: %d\n", tcp.DestinationPort)
	fmt.Fprintf(f.writer, "  Sequence Number:  %d\n", tcp.SequenceNumber)
	fmt.Fprintf(f.writer, "  ACK Number:       %d\n", tcp.AckNumber)
	fmt.Fprintf(f.writer, "  Data Offset:      %d (%d bytes)\n", tcp.DataOffset, int(tcp.DataOffset)*4)
	fmt.Fprintf(f.writer, "  Flags:            0x%02X\n", tcp.Flags)
	fmt.Fprintf(f.writer, "  Window Size:      %d bytes\n", tcp.WindowSize)
	fmt.Fprintf(f.writer, "  Checksum:         0x%04X\n", tcp.Checksum)
	fmt.Fprintf(f.writer, "  Urgent Pointer:   %d\n", tcp.UrgentPointer)
	fmt.Fprintf(f.writer, "  Payload Length:   %d bytes\n", len(tcp.Payload))
}

func (f *Formatter) printWarnings(packet *store.PacketData) {
	if len(packet.Warnings) == 0 {
		return
	}

	fmt.Fprintln(f.writer, "\n[Warnings]")

	for _, warning := range packet.Warnings {
		fmt.Fprintf(f.writer, "  - %s\n", warning)
	}
}

func formatMAC(mac []byte) string {
	if len(mac) != 6 {
		return fmt.Sprintf("%X", mac)
	}

	return net.HardwareAddr(mac).String()
}
