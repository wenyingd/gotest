// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"errors"
	"fmt"
	"k8s.io/klog/v2"
	"net"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/Microsoft/hcsshim"
	"golang.org/x/sys/windows"

	testwindows "windows_net/third_party/windows"
)

func adapterTable(ifindex int) ([]Adapter, error) {
	aas, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	var adapters []Adapter
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
			adapter := Adapter{
				Interface:     ifi,
				CompartmentID: aa.CompartmentId,
			}
			adapters = append(adapters, adapter)
			if ifindex == ifi.Index {
				break
			}
		}
	}
	return adapters, nil
}

// adapterAddresses returns a list of IP adapter and address
// structures. The structure contains an IP adapter and flattened
// multiple IP addresses including unicast, anycast and multicast
// addresses.
// This function is copied from go/src/net/interface_windows.go, the difference is flag
// GAA_FLAG_INCLUDE_ALL_COMPARTMENTS is introduced to query interfaces in all compartments.
func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	flags := uint32(testwindows.GAA_FLAG_INCLUDE_PREFIX | testwindows.GAA_FLAG_INCLUDE_ALL_COMPARTMENTS)
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

type Adapter struct {
	net.Interface
	CompartmentID uint32
}

func (a *Adapter) SetMTU(mtu int, family testwindows.AddressFamily) error {
	runtime.LockOSThread()
	defer func() {
		hcsshim.SetCurrentThreadCompartmentId(0)
		runtime.UnlockOSThread()
	}()
	if err := hcsshim.SetCurrentThreadCompartmentId(a.CompartmentID); err != nil {
		klog.ErrorS(err, "Failed to change current thread's compartment", "compartment", a.CompartmentID)
		return err
	}
	ipInterfaceRow := &testwindows.MibIpInterfaceRow{Family: family, Index: uint32(a.Index)}
	if err := testwindows.GetIPInterfaceEntry(ipInterfaceRow); err != nil {
		return fmt.Errorf("unable to get IPInterface entry with Index %d: %v", a.Index, err)
	}
	ipInterfaceRow.NlMtu = uint32(mtu)
	ipInterfaceRow.SitePrefixLength = 0
	if err := testwindows.SetIPInterfaceEntry(ipInterfaceRow); err != nil {
		return fmt.Errorf("unable to set IPInterface with MTU %d: %v", mtu, err)
	}
	return nil
}

var (
	errInvalidInterfaceName = errors.New("invalid network interface name")
	errNoSuchInterface      = errors.New("no such network interface")
)

func GetAdapterInAllCompartmentsByName(name string) (*Adapter, error) {
	if name == "" {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: errInvalidInterfaceName}
	}
	ift, err := adapterTable(0)
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

func SetInterfaceMTU(name string, mtu int, isIPv6 bool) error {
	adapter, err := GetAdapterInAllCompartmentsByName(name)
	if err != nil {
		return fmt.Errorf("unable to find NetAdapter on host in all compartments with name %s: %v", name, err)
	}
	family := testwindows.AF_INET
	if isIPv6 {
		family = testwindows.AF_INET6
	}
	return adapter.SetMTU(mtu, family)
}
