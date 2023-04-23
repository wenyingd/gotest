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

// copy from internal/syscall/windows/security_windows.go
type LUID struct {
	LowPart  uint32
	HighPart int32
}

type AddressFamily uint16

const (
	AF_UNSPEC AddressFamily = 0
	AF_INET   AddressFamily = 2
	AF_INET6  AddressFamily = 23
)

type RouterDiscoveryBehavior int32

const (
	RouterDiscoveryDisabled  RouterDiscoveryBehavior = 0
	RouterDiscoveryEnabled   RouterDiscoveryBehavior = 1
	RouterDiscoveryDHCP      RouterDiscoveryBehavior = 2
	RouterDiscoveryUnchanged RouterDiscoveryBehavior = -1
)

type LinkLocalAddressBehavior int32

const (
	LinkLocalAlwaysOff LinkLocalAddressBehavior = 0
	LinkLocalDelayed   LinkLocalAddressBehavior = 1
	LinkLocalAlwaysOn  LinkLocalAddressBehavior = 2
	LinkLocalUnchanged LinkLocalAddressBehavior = -1
)

const ScopeLevelCount = 16

type NlInterfaceOffloadRodFlags uint8

const (
	NlChecksumSupported         NlInterfaceOffloadRodFlags = 0x01
	nlOptionsSupported          NlInterfaceOffloadRodFlags = 0x02
	TlDatagramChecksumSupported NlInterfaceOffloadRodFlags = 0x04
	TlStreamChecksumSupported   NlInterfaceOffloadRodFlags = 0x08
	TlStreamOptionsSupported    NlInterfaceOffloadRodFlags = 0x10
	FastPathCompatible          NlInterfaceOffloadRodFlags = 0x20
	TlLargeSendOffloadSupported NlInterfaceOffloadRodFlags = 0x40
	TlGiantSendOffloadSupported NlInterfaceOffloadRodFlags = 0x80
)

type MibIpInterfaceRow struct {
	Family                               AddressFamily
	Luid                                 uint64
	Index                                uint32
	MaxReassemblySize                    uint32
	Identifier                           uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   bool
	ForwardingEnabled                    bool
	WeakHostSend                         bool
	WeakHostReceive                      bool
	UseAutomaticMetric                   bool
	UseNeighborUnreachabilityDetection   bool
	ManagedAddressConfigurationSupported bool
	OtherStatefulConfigurationSupported  bool
	AdvertiseDefaultRoute                bool
	RouterDiscoveryBehavior              RouterDiscoveryBehavior
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMtuDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             LinkLocalAddressBehavior
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [ScopeLevelCount]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NlMtu                                uint32
	Connected                            bool
	SupportsWakeUpPatterns               bool
	SupportsNeighborDiscovery            bool
	SupportsRouterDiscovery              bool
	ReachableTime                        uint32
	TransmitOffload                      NlInterfaceOffloadRodFlags
	ReceiveOffload                       NlInterfaceOffloadRodFlags
	DisableDefaultRoutes                 bool
}

type MibIpInterfaceTable struct {
	NumEntries uint32
	Table      [anysize]*MibIpInterfaceRow
}

var (
	modiphlpapi = syscall.NewLazyDLL(Add("iphlpapi.dll"))

	procGetAdaptersAddresses = modiphlpapi.NewProc("GetAdaptersAddresses")
	procGetIpInterfaceEntry  = modiphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry  = modiphlpapi.NewProc("SetIpInterfaceEntry")
	procGetIpInterfaceTable  = modiphlpapi.NewProc("GetIpInterfaceTable")
)

const anysize = 1

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
	r0, _, _ := syscall.SyscallN(procGetAdaptersAddresses.Addr(), uintptr(family), uintptr(flags), uintptr(reserved), uintptr(unsafe.Pointer(adapterAddresses)), uintptr(unsafe.Pointer(sizePointer)))
	if r0 != 0 {
		errcode = syscall.Errno(r0)
	}
	return
}

func GetIPInterfaceEntry(ipInterfaceRow *MibIpInterfaceRow) (errcode error) {
	r0, _, _ := syscall.SyscallN(procGetIpInterfaceEntry.Addr(), uintptr(unsafe.Pointer(ipInterfaceRow)))
	if r0 != 0 {
		errcode = syscall.Errno(r0)
	}
	return
}

func SetIPInterfaceEntry(ipInterfaceRow *MibIpInterfaceRow) (errcode error) {
	r0, _, _ := syscall.SyscallN(procSetIpInterfaceEntry.Addr(), uintptr(unsafe.Pointer(ipInterfaceRow)))
	if r0 != 0 {
		errcode = syscall.Errno(r0)
	}
	return
}

func GetIPInterfaceTable(family AddressFamily, ipInterfaceTable *MibIpInterfaceTable) (errcode error) {
	r0, _, _ := syscall.SyscallN(procGetIpInterfaceTable.Addr(), uintptr(family), uintptr(unsafe.Pointer(ipInterfaceTable)))
	if r0 != 0 {
		errcode = syscall.Errno(r0)
	}
	return
}
