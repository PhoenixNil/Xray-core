package anytls

import (
	"bytes"
	"encoding/binary"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// udp-over-tcp v2 carries every datagram as
//
//	[uotAddrParser address][uint16 payload length][payload]
//
// when the request is not in connect mode. Note that uotAddrParser uses its own
// address-family bytes (0x00 IPv4 / 0x01 IPv6 / 0x02 FQDN), which differ from the
// socksAddrParser encoding (0x01 / 0x03 / 0x04) that uotRequest itself uses.
// Sending raw payloads without this per-packet header desynchronises the peer,
// which then reads payload bytes where it expects an address family.
//
// In connect mode the request destination applies to every datagram, so the
// per-packet address is omitted and the framing is just
//
//	[uint16 payload length][payload]

// encodeUoTPacket frames a single datagram. It takes ownership of payload.
// In connect mode the address is omitted, so dest is ignored.
func encodeUoTPacket(payload *buf.Buffer, dest net.Destination, connect bool) (buf.MultiBuffer, error) {
	header := buf.New()
	if !connect {
		if err := writeDestination(uotAddrParser, header, dest); err != nil {
			header.Release()
			payload.Release()
			return nil, errors.New("anytls: failed to write UoT address").Base(err)
		}
	}
	var lengthBytes [2]byte
	binary.BigEndian.PutUint16(lengthBytes[:], uint16(payload.Len()))
	if _, err := header.Write(lengthBytes[:]); err != nil {
		header.Release()
		payload.Release()
		return nil, errors.New("anytls: failed to write UoT length").Base(err)
	}
	return buf.MultiBuffer{header, payload}, nil
}

// encodeUoTMulti frames every datagram in mb. Each buffer carries its own
// destination when the dispatcher set one, otherwise fallback is used.
func encodeUoTMulti(mb buf.MultiBuffer, fallback net.Destination, connect bool) (buf.MultiBuffer, error) {
	var out buf.MultiBuffer
	for i, b := range mb {
		if b == nil {
			continue
		}
		mb[i] = nil
		dest := fallback
		if b.UDP != nil {
			dest = *b.UDP
		}
		framed, err := encodeUoTPacket(b, dest, connect)
		if err != nil {
			buf.ReleaseMulti(out)
			buf.ReleaseMulti(mb)
			return nil, err
		}
		out = append(out, framed...)
	}
	return out, nil
}

// parseUoTPacket attempts to decode one framed datagram from the head of b.
// ok is false when b holds only a partial packet and more bytes are needed.
// A non-nil connectDest selects connect mode: the per-packet address is absent
// and every datagram targets connectDest.
func parseUoTPacket(b []byte, connectDest *net.Destination) (dest net.Destination, consumed int, payload []byte, ok bool, err error) {
	if connectDest != nil {
		if len(b) < 2 {
			return
		}
		payloadLen := int(binary.BigEndian.Uint16(b[:2]))
		total := 2 + payloadLen
		if len(b) < total {
			return
		}
		return *connectDest, total, b[2:total], true, nil
	}
	if len(b) < 1 {
		return
	}
	var addrPortLen int
	switch b[0] {
	case 0x00: // IPv4
		addrPortLen = 1 + 4 + 2
	case 0x01: // IPv6
		addrPortLen = 1 + 16 + 2
	case 0x02: // FQDN
		if len(b) < 2 {
			return
		}
		addrPortLen = 1 + 1 + int(b[1]) + 2
	default:
		err = errors.New("anytls: unknown UoT address family: ", b[0])
		return
	}
	if len(b) < addrPortLen+2 {
		return
	}
	payloadLen := int(binary.BigEndian.Uint16(b[addrPortLen : addrPortLen+2]))
	total := addrPortLen + 2 + payloadLen
	if len(b) < total {
		return
	}
	d, e := readDestination(uotAddrParser, bytes.NewReader(b[:addrPortLen]), net.Network_UDP)
	if e != nil {
		err = errors.New("anytls: failed to read UoT address").Base(e)
		return
	}
	return d, total, b[addrPortLen+2 : total], true, nil
}

// uotReassembler turns the anytls byte stream back into datagrams. Frame
// boundaries of cmdPSH do not line up with UoT packet boundaries, so partial
// packets have to be carried across writes.
type uotReassembler struct {
	writer buf.Writer
	// connectDest is non-nil only when the peer negotiated connect mode, in
	// which case datagrams carry no per-packet address.
	connectDest *net.Destination
	pending     []byte
}

func (w *uotReassembler) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if b != nil {
			w.pending = append(w.pending, b.Bytes()...)
		}
	}

	var out buf.MultiBuffer
	for {
		dest, consumed, payload, ok, err := parseUoTPacket(w.pending, w.connectDest)
		if err != nil {
			buf.ReleaseMulti(out)
			return err
		}
		if !ok {
			break
		}
		b := buf.New()
		if _, err := b.Write(payload); err != nil {
			b.Release()
			buf.ReleaseMulti(out)
			return err
		}
		d := dest
		b.UDP = &d
		out = append(out, b)
		w.pending = w.pending[consumed:]
	}

	// Reclaim the head of the backing array once it has been fully consumed.
	if len(w.pending) == 0 {
		w.pending = w.pending[:0]
	}

	if len(out) == 0 {
		return nil
	}
	return w.writer.WriteMultiBuffer(out)
}

func (w *uotReassembler) Close() error {
	return common.Close(w.writer)
}

func (w *uotReassembler) Interrupt() {
	common.Interrupt(w.writer)
}
