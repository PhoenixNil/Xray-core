package anytls

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// wireFrame encodes one anytls frame as it appears on the wire.
func wireFrame(cmd byte, sid uint32, body []byte) []byte {
	b := make([]byte, 7+len(body))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(body)))
	copy(b[7:], body)
	return b
}

type recordingConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(p))
	return len(p), nil
}

func TestSendStreamDataWritesOncePerPSH(t *testing.T) {
	conn := new(recordingConn)
	bw := buf.NewBufferedWriter(buf.NewWriter(conn))
	s := &session{conn: conn, bw: bw, fw: newFrameWriter(bw)}
	const sid = 0x12345678
	first := bytes.Repeat([]byte("abc"), maxFramePayload/3)
	tail := []byte("tail")
	data := append(buf.MergeBytes(nil, first), buf.FromBytes(tail))
	if err := s.sendStreamData(sid, data, 0); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("got %d writes for two PSH frames", len(conn.writes))
	}
	for i, body := range [][]byte{first, tail} {
		if !bytes.Equal(conn.writes[i], wireFrame(cmdPSH, sid, body)) {
			t.Errorf("write %d did not contain the complete PSH frame", i)
		}
	}
}

// frameReader feeds the given frames to readLoop, followed by EOF.
func frameReader(frames ...[]byte) *buf.BufferedReader {
	return &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(bytes.Join(frames, nil)))}
}

// failingWriter stands in for a local connection the app already closed.
type failingWriter struct{}

func (failingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return io.ErrClosedPipe
}

// After this side closes a stream, the peer keeps sending whatever it had in
// flight until our FIN reaches it. readLoop must drop that data and carry on;
// it used to return nil here, which left the session in the idle pool with no
// reader, so the next stream on it stalled for the full SYNACK timeout.
func TestReadLoopDropsLateDataForClosedStream(t *testing.T) {
	_, s := newPooledTestSession()
	synAck := make(chan error, 1)
	s.synAckCh[9] = synAck
	s.br = frameReader(
		wireFrame(cmdPSH, 7, []byte("late payload")),
		wireFrame(cmdSYNACK, 9, nil),
	)

	if err := s.readLoop(context.Background()); err != io.EOF {
		t.Fatalf("readLoop returned %v, want io.EOF after consuming every frame", err)
	}
	select {
	case err := <-synAck:
		if err != nil {
			t.Fatalf("SYNACK delivered error %v, want nil", err)
		}
	default:
		t.Fatal("the SYNACK queued behind the late frame was never processed")
	}
	if s.isClosed() {
		t.Error("session was closed")
	}
}

// A local write that fails because the app went away must finish only that
// stream. Returning the error used to tear down the whole pooled session, so
// every aborted download cost the next request a fresh TLS handshake.
func TestReadLoopLocalWriteErrorFinishesOnlyThatStream(t *testing.T) {
	c, s := newPooledTestSession()
	uplink, _ := pipe.New(pipe.WithoutSizeLimit())
	st, err := s.openStream(context.Background(), net.TCPDestination(net.ParseAddress("example.com"), 443),
		&transport.Link{Reader: uplink, Writer: failingWriter{}})
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	synAck := make(chan error, 1)
	s.synAckCh[99] = synAck
	s.br = frameReader(
		wireFrame(cmdPSH, st.sid, []byte("abc")),  // local write fails: finish the stream
		wireFrame(cmdPSH, st.sid, []byte("late")), // stream is gone now: dropped
		wireFrame(cmdSYNACK, 99, nil),             // the session must still be read
	)

	if err := s.readLoop(context.Background()); err != io.EOF {
		t.Fatalf("readLoop returned %v, want io.EOF after consuming every frame", err)
	}
	select {
	case <-st.done:
	default:
		t.Fatal("the stream whose local write failed was not finished")
	}
	if got := st.result(); got != io.ErrClosedPipe {
		t.Errorf("stream result = %v, want the local write error", got)
	}
	if s.isClosed() {
		t.Fatal("session was closed because of one stream's local write error")
	}
	select {
	case err := <-synAck:
		if err != nil {
			t.Fatalf("SYNACK delivered error %v, want nil", err)
		}
	default:
		t.Fatal("frames after the failed write were never processed")
	}
	if got, err := c.takeIdleSession(); err != nil || got != s {
		t.Errorf("takeIdleSession() = (%p, %v), want the same session back in the pool", got, err)
	}
}
