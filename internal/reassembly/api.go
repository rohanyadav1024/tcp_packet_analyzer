package reassembly

import (
	"context"
	"sync"
)

type PushToChannelCallback func(ctx context.Context, packet []byte) error

type Reassembly struct {
	manager *ReassemblyManager
}

var (
	reassemblyInstance *Reassembly
	once               sync.Once
)

func CreateReassembly(
	pushToTransportChannel PushToChannelCallback,
	pushToDiscardChannel PushToChannelCallback,
) *Reassembly {

	once.Do(func() {
		// Manager owns and initializes all Reassembly resources.
		manager := NewReassemblyManager(
			pushToTransportChannel,
			pushToDiscardChannel,
		)

		reassemblyInstance = &Reassembly{
			manager: manager,
		}

		// Start all Reassembly resources.
		manager.Start()
	})

	return reassemblyInstance
}

func DisposeReassembly() {
	if reassemblyInstance != nil {
		reassemblyInstance.manager.Stop()
		reassemblyInstance = nil
	}
}

func GetReassemblyInstance() *Reassembly {
	return reassemblyInstance
}

// PushToReassembly pushes a packet into the Reassembly input channel.
func (r *Reassembly) PushToReassembly(
	ctx context.Context,
	req AssemblyPacketRequest,
) error {

	if ok := r.manager.rsmblychannel.Push(ctx, req); ok {
		return nil
	}

	return ctx.Err()
}
