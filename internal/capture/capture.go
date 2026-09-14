package capture

import (
	"time"

	"github.com/google/gopacket"
	pcap "github.com/google/gopacket/pcap"
)

type Capture struct {
	handle *pcap.Handle
}

func NewCapture(device string, snaplen int32, promisc bool, timeout time.Duration) (*Capture, error) {
	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		return nil, err
	}

	return &Capture{handle: handle}, nil
}

func NewCaptureFromFile(filename string) (*Capture, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}

	return &Capture{handle: handle}, nil
}

func (c *Capture) Close() {
	defer c.handle.Close()
}

func (c *Capture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := c.handle.ReadPacketData()
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}

	return data, ci, nil
}
