// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package windows

import (
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const GAA_FLAG_INCLUDE_PREFIX = 0x00000010
const GAA_FLAG_INCLUDE_ALL_COMPARTMENTS = 0x00000200

const (
	IF_TYPE_OTHER              = 1
	IF_TYPE_ETHERNET_CSMACD    = 6
	IF_TYPE_ISO88025_TOKENRING = 9
	IF_TYPE_PPP                = 23
	IF_TYPE_SOFTWARE_LOOPBACK  = 24
	IF_TYPE_ATM                = 37
	IF_TYPE_IEEE80211          = 71
	IF_TYPE_TUNNEL             = 131
	IF_TYPE_IEEE1394           = 144
)

const (
	IfOperStatusUp             = 1
	IfOperStatusDown           = 2
	IfOperStatusTesting        = 3
	IfOperStatusUnknown        = 4
	IfOperStatusDormant        = 5
	IfOperStatusNotPresent     = 6
	IfOperStatusLowerLayerDown = 7
)

type SocketAddress struct {
	Sockaddr       *syscall.RawSockaddrAny
	SockaddrLength int32
}

type IpAdapterUnicastAddress struct {
	Length             uint32
	Flags              uint32
	Next               *IpAdapterUnicastAddress
	Address            SocketAddress
	PrefixOrigin       int32
	SuffixOrigin       int32
	DadState           int32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	LeaseLifetime      uint32
	OnLinkPrefixLength uint8
}

type IpAdapterAnycastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *IpAdapterAnycastAddress
	Address SocketAddress
}

type IpAdapterMulticastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *IpAdapterMulticastAddress
	Address SocketAddress
}

type IpAdapterDnsServerAdapter struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterDnsServerAdapter
	Address  SocketAddress
}

type IpAdapterPrefix struct {
	Length       uint32
	Flags        uint32
	Next         *IpAdapterPrefix
	Address      SocketAddress
	PrefixLength uint32
}

type IpAdapterAddresses struct {
	Length                uint32
	IfIndex               uint32
	Next                  *IpAdapterAddresses
	AdapterName           *byte
	FirstUnicastAddress   *IpAdapterUnicastAddress
	FirstAnycastAddress   *IpAdapterAnycastAddress
	FirstMulticastAddress *IpAdapterMulticastAddress
	FirstDnsServerAddress *IpAdapterDnsServerAdapter
	DnsSuffix             *uint16
	Description           *uint16
	FriendlyName          *uint16
	PhysicalAddress       [syscall.MAX_ADAPTER_ADDRESS_LENGTH]byte
	PhysicalAddressLength uint32
	Flags                 uint32
	Mtu                   uint32
	IfType                uint32
	OperStatus            uint32
	Ipv6IfIndex           uint32
	ZoneIndices           [16]uint32
	FirstPrefix           *IpAdapterPrefix
	/* more fields might be present here. */
}

type FILE_BASIC_INFO struct {
	CreationTime   syscall.Filetime
	LastAccessTime syscall.Filetime
	LastWriteTime  syscall.Filetime
	ChangedTime    syscall.Filetime
	FileAttributes uint32
}

// IsSystemDLL reports whether the named dll key (a base name, like
// "foo.dll") is a system DLL which should only be loaded from the
// Windows SYSTEM32 directory.
//
// Filenames are case sensitive, but that doesn't matter because
// the case registered with Add is also the same case used with
// LoadDLL later.
//
// It has no associated mutex and should only be mutated serially
// (currently: during init), and not concurrent with DLL loading.
var IsSystemDLL = map[string]bool{}

// Add notes that dll is a system32 DLL which should only be loaded
// from the Windows SYSTEM32 directory. It returns its argument back,
// for ease of use in generated code.
func Add(dll string) string {
	IsSystemDLL[dll] = true
	return dll
}

var (
	modiphlpapi = syscall.NewLazyDLL(Add("iphlpapi.dll"))

	procGetAdaptersAddresses = modiphlpapi.NewProc("GetAdaptersAddresses")
)

// UTF16PtrToString is like UTF16ToString, but takes *uint16
// as a parameter instead of []uint16.
func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	// Find NUL terminator.
	end := unsafe.Pointer(p)
	n := 0
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		n++
	}
	// Turn *uint16 into []uint16.
	var s []uint16
	hdr := (*Slice)(unsafe.Pointer(&s))
	hdr.Data = unsafe.Pointer(p)
	hdr.Cap = n
	hdr.Len = n
	// Decode []uint16 into string.
	return string(utf16.Decode(s))
}

func GetAdaptersAddresses(family uint32, flags uint32, reserved uintptr, adapterAddresses *IpAdapterAddresses, sizePointer *uint32) (errcode error) {
	r0, _, _ := syscall.Syscall6(procGetAdaptersAddresses.Addr(), 5, uintptr(family), uintptr(flags), uintptr(reserved), uintptr(unsafe.Pointer(adapterAddresses)), uintptr(unsafe.Pointer(sizePointer)), 0)
	if r0 != 0 {
		errcode = syscall.Errno(r0)
	}
	return
}
