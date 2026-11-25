package anytls

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type collectingWriter struct {
	got buf.MultiBuffer
}

func (w *collectingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.got = append(w.got, mb...)
	return nil
}

func (w *collectingWriter) Close() error {
	return nil
}

type datagram struct {
	dest    net.Destination
	payload []byte
}

func encodeDatagrams(t *testing.T, packets []datagram, connect bool) []byte {
	t.Helper()

	var mb buf.MultiBuffer
	for _, p := range packets {
		b := buf.New()
		if _, err := b.Write(p.payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		d := p.dest
		b.UDP = &d
		mb = append(mb, b)
	}

	framed, err := encodeUoTMulti(mb, net.Destination{}, connect)
	if err != nil {
		t.Fatalf("encodeUoTMulti: %v", err)
	}
	defer buf.ReleaseMulti(framed)

	var wire []byte
	for _, b := range framed {
		wire = append(wire, b.Bytes()...)
	}
	return wire
}

// feed writes wire to a reassembler in chunks of the given size, mimicking the
// way cmdPSH frame boundaries cut across UoT packet boundaries.
func feed(t *testing.T, wire []byte, chunk int, connectDest *net.Destination) buf.MultiBuffer {
	t.Helper()

	w := &collectingWriter{}
	r := &uotReassembler{writer: w, connectDest: connectDest}
	for i := 0; i < len(wire); i += chunk {
		end := i + chunk
		if end > len(wire) {
			end = len(wire)
		}
		b := buf.New()
		if _, err := b.Write(wire[i:end]); err != nil {
			t.Fatalf("write chunk: %v", err)
		}
		if err := r.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("reassemble: %v", err)
		}
	}
	if len(r.pending) != 0 {
		t.Fatalf("reassembler left %d bytes pending", len(r.pending))
	}
	return w.got
}

func TestUoTRoundTrip(t *testing.T) {
	packets := []datagram{
		{net.UDPDestination(net.ParseAddress("8.8.8.8"), 53), []byte("query-v4")},
		{net.UDPDestination(net.ParseAddress("2001:4860:4860::8888"), 53), []byte("query-v6")},
		{net.UDPDestination(net.ParseAddress("dns.example.com"), 5353), []byte("query-fqdn")},
		{net.UDPDestination(net.ParseAddress("1.1.1.1"), 853), nil},
	}

	wire := encodeDatagrams(t, packets, false)

	// One chunk per byte is the worst case for reassembly; len(wire) is the
	// single-frame case. Both must yield the same datagrams.
	for _, chunk := range []int{1, 3, len(wire)} {
		got := feed(t, wire, chunk, nil)
		if len(got) != len(packets) {
			t.Fatalf("chunk=%d: got %d datagrams, want %d", chunk, len(got), len(packets))
		}
		for i, b := range got {
			if b.UDP == nil {
				t.Fatalf("chunk=%d packet=%d: missing destination", chunk, i)
			}
			if *b.UDP != packets[i].dest {
				t.Errorf("chunk=%d packet=%d: dest = %v, want %v", chunk, i, *b.UDP, packets[i].dest)
			}
			if !bytes.Equal(b.Bytes(), packets[i].payload) {
				t.Errorf("chunk=%d packet=%d: payload = %q, want %q", chunk, i, b.Bytes(), packets[i].payload)
			}
		}
		buf.ReleaseMulti(got)
	}
}

func TestUoTRoundTripConnectMode(t *testing.T) {
	dest := net.UDPDestination(net.ParseAddress("8.8.4.4"), 53)
	packets := []datagram{
		{dest, []byte("first")},
		{dest, []byte("second")},
	}

	wire := encodeDatagrams(t, packets, true)

	// Connect mode omits the per-packet address, so the wire is exactly
	// 2 length bytes plus the payload for each datagram.
	wantLen := 2 + len("first") + 2 + len("second")
	if len(wire) != wantLen {
		t.Fatalf("wire length = %d, want %d (address must be omitted)", len(wire), wantLen)
	}

	got := feed(t, wire, 1, &dest)
	defer buf.ReleaseMulti(got)
	if len(got) != len(packets) {
		t.Fatalf("got %d datagrams, want %d", len(got), len(packets))
	}
	for i, b := range got {
		if b.UDP == nil || *b.UDP != dest {
			t.Errorf("packet %d: dest = %v, want %v", i, b.UDP, dest)
		}
		if !bytes.Equal(b.Bytes(), packets[i].payload) {
			t.Errorf("packet %d: payload = %q, want %q", i, b.Bytes(), packets[i].payload)
		}
	}
}

// A raw payload written without framing is what the server used to send. The
// decoder must reject it rather than silently desynchronising.
func TestUoTRejectsUnframedPayload(t *testing.T) {
	w := &collectingWriter{}
	r := &uotReassembler{writer: w}

	b := buf.New()
	// 0xFF is not a valid uot.AddrParser address family.
	if _, err := b.Write([]byte{0xFF, 0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := r.WriteMultiBuffer(buf.MultiBuffer{b}); err == nil {
		t.Fatal("expected an error for an unframed payload, got nil")
	}
}
