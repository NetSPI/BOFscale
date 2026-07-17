package netstack

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	icmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	icmp6CreateFile = iphlpapi.NewProc("Icmp6CreateFile")
	icmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	icmp6SendEcho2  = iphlpapi.NewProc("Icmp6SendEcho2")
	icmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
)

type IpOptionInformation struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type IcmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       IpOptionInformation
}

type IPv6Addr struct {
	Addr [16]byte
}

type SockaddrIn6 struct {
	Family   uint16
	Port     uint16
	FlowInfo uint32
	Addr     IPv6Addr
	ScopeId  uint32
}

type Icmpv6EchoReply struct {
	Address       SockaddrIn6
	Status        uint32
	RoundTripTime uint32
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

func uint32ToIPv4(addr uint32) net.IP {
	ip := make([]byte, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return net.IP(ip)
}

func pingIPv4(ip net.IP, timeout uint32) (*PingResult, error) {
	destAddr := ipv4ToUint32(ip)

	handle, _, err := icmpCreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) {
		return nil, fmt.Errorf("IcmpCreateFile failed: %v", err)
	}
	defer icmpCloseHandle.Call(handle)

	sendData := []byte("ABCDEFGHIJKLMNOP")
	sendSize := uint16(len(sendData))

	replySize := uint32(unsafe.Sizeof(IcmpEchoReply{})) + uint32(sendSize) + 8 + 256
	replyBuffer := make([]byte, replySize)

	ret, _, err := icmpSendEcho.Call(
		handle,
		uintptr(destAddr),
		uintptr(unsafe.Pointer(&sendData[0])),
		uintptr(sendSize),
		0,
		uintptr(unsafe.Pointer(&replyBuffer[0])),
		uintptr(replySize),
		uintptr(timeout),
	)

	if ret == 0 {
		// err from syscall contains the actual Windows error
		errno, ok := err.(syscall.Errno)
		if ok {
			return nil, fmt.Errorf("IcmpSendEcho failed: %v (errno %d)", err, uint32(errno))
		}
		return nil, fmt.Errorf("IcmpSendEcho failed: %v", err)
	}

	reply := (*IcmpEchoReply)(unsafe.Pointer(&replyBuffer[0]))

	return &PingResult{
		Address:       uint32ToIPv4(reply.Address),
		Status:        reply.Status,
		RoundTripTime: reply.RoundTripTime,
		TTL:           reply.Options.Ttl,
		DataSize:      reply.DataSize,
		IsIPv6:        false,
	}, nil
}

func pingIPv6(ip net.IP, timeout uint32) (*PingResult, error) {
	handle, _, err := icmp6CreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) {
		return nil, fmt.Errorf("Icmp6CreateFile failed: %v", err)
	}
	defer icmpCloseHandle.Call(handle)

	var sourceAddr SockaddrIn6
	sourceAddr.Family = syscall.AF_INET6

	var destAddr SockaddrIn6
	destAddr.Family = syscall.AF_INET6
	copy(destAddr.Addr.Addr[:], ip.To16())

	sendData := []byte("ABCDEFGHIJKLMNOP")
	sendSize := uint16(len(sendData))

	replySize := uint32(unsafe.Sizeof(Icmpv6EchoReply{})) + uint32(sendSize) + 8 + 256
	replyBuffer := make([]byte, replySize)

	ret, _, err := icmp6SendEcho2.Call(
		handle,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&sourceAddr)),
		uintptr(unsafe.Pointer(&destAddr)),
		uintptr(unsafe.Pointer(&sendData[0])),
		uintptr(sendSize),
		0,
		uintptr(unsafe.Pointer(&replyBuffer[0])),
		uintptr(replySize),
		uintptr(timeout),
	)

	if ret == 0 {
		errno, ok := err.(syscall.Errno)
		if ok {
			return nil, fmt.Errorf("Icmp6SendEcho2 failed: %v (errno %d)", err, uint32(errno))
		}
		return nil, fmt.Errorf("Icmp6SendEcho2 failed: %v", err)
	}

	reply := (*Icmpv6EchoReply)(unsafe.Pointer(&replyBuffer[0]))

	return &PingResult{
		Address:       net.IP(reply.Address.Addr.Addr[:]),
		Status:        reply.Status,
		RoundTripTime: reply.RoundTripTime,
		TTL:           0,
		DataSize:      sendSize,
		IsIPv6:        true,
	}, nil
}

func Ping(target string, timeout uint32) (*PingResult, error) {
	ipAddr, err := net.ResolveIPAddr("ip4", target)
	if err == nil && ipAddr.IP.To4() != nil {
		return pingIPv4(ipAddr.IP, timeout)
	}

	ipAddr, err = net.ResolveIPAddr("ip6", target)
	if err == nil {
		return pingIPv6(ipAddr.IP, timeout)
	}

	return nil, fmt.Errorf("failed to resolve address: %s", target)
}
