// SPDX-License-Identifier: Apache-2.0
package uniontun

import (
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Device admits all app traffic, retaining the actual AWG packet path for the
// union. Only known unselected TCP/UDP flows enter the protected direct stack.
type Device struct {
	tun.Device
	policy     *policy
	direct     *directStack
	readMu     sync.Mutex
	writeMu    sync.Mutex
	closeOnce  sync.Once
	closeError error
}

func New(raw tun.Device, config string, owner Owner, protect func(int) bool) (*Device, error) {
	p, err := newPolicy(config, owner)
	if err != nil {
		return nil, err
	}
	d := &Device{Device: raw, policy: p}
	mtu, err := raw.MTU()
	if err != nil {
		return nil, err
	}
	d.direct, err = newDirectStack(mtu, protect, func(packet []byte) error {
		_, err := d.Write([][]byte{packet}, 0)
		return err
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Device) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	for {
		n, err := d.Device.Read(buffers, sizes, offset)
		kept := 0
		for i := 0; i < n; i++ {
			packet := buffers[i][offset : offset+sizes[i]]
			if d.policy.throughVPN(packet, time.Now()) {
				if kept != i {
					copy(buffers[kept][offset:], packet)
				}
				sizes[kept] = sizes[i]
				kept++
			} else {
				d.direct.inject(packet)
			}
		}
		if kept > 0 || err != nil {
			return kept, err
		}
	}
}

func (d *Device) Write(buffers [][]byte, offset int) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.Device.Write(buffers, offset)
}

func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		// Closing the owned TUN releases a blocked reader/output before waiting
		// for forwarders. No bypass socket survives device cleanup.
		d.closeError = d.Device.Close()
		d.direct.close()
	})
	return d.closeError
}
