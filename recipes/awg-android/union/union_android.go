// SPDX-License-Identifier: Apache-2.0
package main

// #include "union_bridge.h"
import "C"

import (
	"errors"
	"net/netip"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-android/uniontun"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

//export awgTurnOnUnion
func awgTurnOnUnion(name string, fd int32, settings string, callbacks C.uintptr_t, policy string) int32 {
	return turnOn(name, fd, settings, uintptr(callbacks), policy)
}

func releaseUnionBridge(opaque uintptr) { C.amnezia_union_release(C.uintptr_t(opaque)) }

type protectedBind struct {
	conn.Bind
	conn.PeekLookAtSocketFd
	protect func(int) bool
}

// Some Android bind implementations leave one family unavailable and their
// PeekLookAtSocketFd method dereferences a nil family socket in that case.
// Treat that path as an unavailable family so Open can still use the other
// protected socket, while a bind with no usable descriptors fails closed.
func safePeekSocket(peek conn.PeekLookAtSocketFd, ipv6 bool) (fd int, err error) {
	fd = -1
	defer func() {
		if recovered := recover(); recovered != nil {
			fd = -1
			err = errors.New("VPN socket descriptor unavailable")
		}
	}()
	if ipv6 {
		return peek.PeekLookAtSocketFd6()
	}
	return peek.PeekLookAtSocketFd4()
}

func (b *protectedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	receivers, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	fd4, err4 := safePeekSocket(b.PeekLookAtSocketFd, false)
	fd6, err6 := safePeekSocket(b.PeekLookAtSocketFd, true)
	if (fd4 < 0 && fd6 < 0) || (err4 != nil && err6 != nil) || (fd4 >= 0 && !b.protect(fd4)) || (fd6 >= 0 && !b.protect(fd6)) {
		b.Bind.Close()
		return nil, 0, errors.New("VPN socket protection failed")
	}
	return receivers, actualPort, nil
}

func newUnionBackend(raw tun.Device, bind conn.Bind, opaque uintptr, policy string) (tun.Device, conn.Bind, error) {
	protect := func(fd int) bool { return C.amnezia_union_protect(C.uintptr_t(opaque), C.int(fd)) == 1 }
	owner := func(protocol int, source, destination netip.AddrPort) int {
		sourceBytes, destinationBytes := source.Addr().AsSlice(), destination.Addr().AsSlice()
		return int(C.amnezia_union_owner(C.uintptr_t(opaque), C.int(protocol), unsafe.Pointer(&sourceBytes[0]),
			C.int(len(sourceBytes)), C.int(source.Port()), unsafe.Pointer(&destinationBytes[0]),
			C.int(len(destinationBytes)), C.int(destination.Port())))
	}
	peek, ok := bind.(conn.PeekLookAtSocketFd)
	if !ok {
		return raw, bind, errors.New("VPN socket descriptors unavailable")
	}
	device, err := uniontun.New(raw, policy, owner, protect)
	if err != nil {
		return raw, bind, err
	}
	return device, &protectedBind{Bind: bind, PeekLookAtSocketFd: peek, protect: protect}, nil
}
