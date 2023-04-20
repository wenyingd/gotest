// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"errors"
	"net"
	"os"
	"syscall"
	"unsafe"

	"windows_net/third_party/windows"
)

// adapterAddresses returns a list of IP adapter and address
// structures. The structure contains an IP adapter and flattened
// multiple IP addresses including unicast, anycast and multicast
// addresses.
func adapterAddresses(flags uint32) ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return nil, nil
			}
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
		if l <= uint32(len(b)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}

// If the ifindex is zero, interfaceTable returns mappings of all
// network interfaces. Otherwise it returns a mapping of a specific
// interface.
func interfaceTable(ifindex int, flags uint32) ([]net.Interface, error) {
	aas, err := adapterAddresses(flags)
	if err != nil {
		return nil, err
	}
	var ift []net.Interface
	for _, aa := range aas {
		index := aa.IfIndex
		if index == 0 { // ipv6IfIndex is a substitute for ifIndex
			index = aa.Ipv6IfIndex
		}
		if ifindex == 0 || ifindex == int(index) {
			ifi := net.Interface{
				Index: int(index),
				Name:  windows.UTF16PtrToString(aa.FriendlyName),
			}
			if aa.OperStatus == windows.IfOperStatusUp {
				ifi.Flags |= net.FlagUp
			}
			// For now we need to infer link-layer service
			// capabilities from media types.
			// TODO: use MIB_IF_ROW2.AccessType now that we no longer support
			// Windows XP.
			switch aa.IfType {
			case windows.IF_TYPE_ETHERNET_CSMACD, windows.IF_TYPE_ISO88025_TOKENRING, windows.IF_TYPE_IEEE80211, windows.IF_TYPE_IEEE1394:
				ifi.Flags |= net.FlagBroadcast | net.FlagMulticast
			case windows.IF_TYPE_PPP, windows.IF_TYPE_TUNNEL:
				ifi.Flags |= net.FlagPointToPoint | net.FlagMulticast
			case windows.IF_TYPE_SOFTWARE_LOOPBACK:
				ifi.Flags |= net.FlagLoopback | net.FlagMulticast
			case windows.IF_TYPE_ATM:
				ifi.Flags |= net.FlagBroadcast | net.FlagPointToPoint | net.FlagMulticast // assume all services available; LANE, point-to-point and point-to-multipoint
			}
			if aa.Mtu == 0xffffffff {
				ifi.MTU = -1
			} else {
				ifi.MTU = int(aa.Mtu)
			}
			if aa.PhysicalAddressLength > 0 {
				ifi.HardwareAddr = make(net.HardwareAddr, aa.PhysicalAddressLength)
				copy(ifi.HardwareAddr, aa.PhysicalAddress[:])
			}
			ift = append(ift, ifi)
			if ifindex == ifi.Index {
				break
			}
		}
	}
	return ift, nil
}

var (
	errInvalidInterface         = errors.New("invalid network interface")
	errInvalidInterfaceIndex    = errors.New("invalid network interface index")
	errInvalidInterfaceName     = errors.New("invalid network interface name")
	errNoSuchInterface          = errors.New("no such network interface")
	errNoSuchMulticastInterface = errors.New("no such multicast network interface")
)

// InterfaceByNameInAllCompartments returns the interface specified by name.
func InterfaceByNameInAllCompartments(name string) (*net.Interface, error) {
	if name == "" {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errInvalidInterfaceName}
	}
	flags := uint32(windows.GAA_FLAG_INCLUDE_PREFIX | windows.GAA_FLAG_INCLUDE_ALL_COMPARTMENTS)
	ift, err := interfaceTable(0, flags)
	if err != nil {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: err}
	}
	for _, ifi := range ift {
		if name == ifi.Name {
			return &ifi, nil
		}
	}
	return nil, &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errNoSuchInterface}
}
