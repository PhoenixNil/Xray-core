package anytls

import (
	"io"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

// uotMagicAddress is the destination a client puts in the SYN of a
// udp-over-tcp v2 stream.
const uotMagicAddress = "sp.v2.udp-over-tcp.arpa"

// socksAddrParser encodes [ATYP][address][port] the SOCKS5 way, with ATYP
// 0x01 IPv4 / 0x03 domain / 0x04 IPv6. The anytls SYN body and the
// udp-over-tcp request both use it.
var socksAddrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
)

// uotAddrParser is the per-datagram address of udp-over-tcp v2. The layout is
// the same but the family bytes are its own: 0x00 IPv4 / 0x01 IPv6 / 0x02 domain.
var uotAddrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x00, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x02, net.AddressFamilyDomain),
)

func readDestination(parser protocol.AddressSerializer, reader io.Reader, network net.Network) (net.Destination, error) {
	addr, port, err := parser.ReadAddressPort(nil, reader)
	if err != nil {
		return net.Destination{}, err
	}
	return net.Destination{Network: network, Address: addr, Port: port}, nil
}

func writeDestination(parser protocol.AddressSerializer, writer io.Writer, dest net.Destination) error {
	if dest.Address == nil {
		return errors.New("anytls: destination has no address")
	}
	return parser.WriteAddressPort(writer, dest.Address, dest.Port)
}

// uotRequest opens a udp-over-tcp v2 stream: [isConnect byte][socks address].
type uotRequest struct {
	IsConnect   bool
	Destination net.Destination
}

func readUoTRequest(reader io.Reader) (*uotRequest, error) {
	var isConnect [1]byte
	if _, err := io.ReadFull(reader, isConnect[:]); err != nil {
		return nil, err
	}
	dest, err := readDestination(socksAddrParser, reader, net.Network_UDP)
	if err != nil {
		return nil, err
	}
	return &uotRequest{IsConnect: isConnect[0] != 0, Destination: dest}, nil
}

func writeUoTRequest(writer io.Writer, request uotRequest) error {
	var isConnect [1]byte
	if request.IsConnect {
		isConnect[0] = 1
	}
	if _, err := writer.Write(isConnect[:]); err != nil {
		return err
	}
	return writeDestination(socksAddrParser, writer, request.Destination)
}
