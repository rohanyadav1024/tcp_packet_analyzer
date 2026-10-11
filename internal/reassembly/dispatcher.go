package reassembly

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"sync"

	"github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
)

type Dispatcher struct {
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	runOnce sync.Once

	totalPools int
	pools      []*MessageQueue
	rlyc       *channels.Channel[AssemblyPacketRequest]
}

func NewDispatcher(
	pools []*MessageQueue,
	rlyc *channels.Channel[AssemblyPacketRequest],
) (*Dispatcher, error) {
	if len(pools) == 0 {
		return nil, errors.New("dispatcher requires at least one pool")
	}

	for i, pool := range pools {
		if pool == nil {
			return nil, errors.New("dispatcher contains a nil pool")
		}
		_ = i
	}

	if rlyc == nil {
		return nil, errors.New("dispatcher requires an input channel")
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Dispatcher{
		ctx:        ctx,
		cancel:     cancel,
		pools:      pools,
		totalPools: len(pools),
		rlyc:       rlyc,
	}, nil
}

// Run starts the dispatcher once.
func (d *Dispatcher) Run() {
	d.runOnce.Do(func() {
		d.wg.Add(1)
		go d.worker()
	})
}

// Stop cancels the dispatcher and waits for it to exit.
func (d *Dispatcher) Stop() {
	d.cancel()
	d.wg.Wait()
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()

	for {
		rPacket, ok := d.rlyc.Pop(d.ctx)
		if !ok {
			return
		}

		poolIndex := d.poolIndex(rPacket.AssemblyLineKey)

		d.pools[poolIndex].Enqueue(d.ctx, Message{
			MessageTypePacket,
			rPacket,
		})

		// ToDo: error reporting.
	}
}

func (d *Dispatcher) poolIndex(k AssemblyLineKey) int {
	return int(hash(k) % uint32(d.totalPools))
}

func hash(k AssemblyLineKey) uint32 {
	h := fnv.New32a()

	_, _ = h.Write(k.SourceIP[:])
	_, _ = h.Write(k.DestinationIP[:])
	_, _ = h.Write([]byte{k.Protocol})

	var id [2]byte
	binary.BigEndian.PutUint16(id[:], k.Identification)
	_, _ = h.Write(id[:])

	return h.Sum32()
}
