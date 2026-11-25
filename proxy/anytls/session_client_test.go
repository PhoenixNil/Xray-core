package anytls

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// newPooledTestSession builds a client session wired to a recording writer,
// registered with a Client that owns an idle pool.
func newPooledTestSession() (*Client, *session) {
	c := &Client{
		paddingScheme: getDefaultPaddingScheme(),
		sessions:      make(map[uint64]*session),
	}
	c.authPadding = getPadding0Size(c.paddingScheme)

	s := &session{
		isClient:      true,
		client:        c,
		bw:            buf.NewBufferedWriter(&recordingWriter{}),
		paddingScheme: c.paddingScheme,
		streams:       make(map[uint32]*stream),
		synAckCh:      make(map[uint32]chan error),
		errCh:         make(chan error, 1),
		seq:           1,
	}
	s.fw = newFrameWriter(s.bw)
	s.peerVersion.Store(1)
	c.sessions[s.seq] = s
	return c, s
}

func newTestLink() *transport.Link {
	r, w := pipe.New(pipe.WithoutSizeLimit())
	return &transport.Link{Reader: r, Writer: w}
}

// A FIN can arrive the instant the SYN is on the wire, so the stream must carry
// its dieHook before readLoop can reach it. Installing the hook after openStream
// returns loses the race: the close still decrements activeStreams, but the
// session is never marked idle, so takeIdleSession can never reuse it and
// cleanupIdleSessions never times it out — both only walk idleSessions.
func TestOpenStreamInstallsDieHookBeforeReturning(t *testing.T) {
	c, s := newPooledTestSession()

	st, err := s.openStream(context.Background(), net.TCPDestination(net.ParseAddress("example.com"), 443), newTestLink())
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	if st.dieHook == nil {
		t.Fatal("dieHook is nil on return from openStream; a FIN arriving now would strand the session")
	}
	if got := s.activeStreams.Load(); got != 1 {
		t.Fatalf("activeStreams = %d, want 1", got)
	}

	// What readLoop does on cmdFIN, run at the earliest moment it could happen.
	s.finishStream(st.sid, nil)

	if got := s.activeStreams.Load(); got != 0 {
		t.Errorf("activeStreams = %d, want 0", got)
	}
	if !s.inIdlePool.Load() {
		t.Error("session was not marked idle, so it can never be reused or timed out")
	}
	if len(c.idleSessions) != 1 || c.idleSessions[0] != s.seq {
		t.Errorf("idleSessions = %v, want [%d]", c.idleSessions, s.seq)
	}
	if got, err := c.takeIdleSession(); err != nil || got != s {
		t.Errorf("takeIdleSession() = (%p, %v), want (%p, nil)", got, err, s)
	}
}

// A session still serving another stream must not be handed back to the pool.
func TestDieHookKeepsBusySessionOutOfPool(t *testing.T) {
	c, s := newPooledTestSession()

	first, err := s.openStream(context.Background(), net.TCPDestination(net.ParseAddress("example.com"), 443), newTestLink())
	if err != nil {
		t.Fatalf("openStream first: %v", err)
	}
	if _, err := s.openStream(context.Background(), net.TCPDestination(net.ParseAddress("example.org"), 443), newTestLink()); err != nil {
		t.Fatalf("openStream second: %v", err)
	}

	s.finishStream(first.sid, nil)

	if s.inIdlePool.Load() {
		t.Error("session went idle while a second stream was still active")
	}
	if len(c.idleSessions) != 0 {
		t.Errorf("idleSessions = %v, want empty", c.idleSessions)
	}
}

func TestClientCloseStopsCleanupAndClosesSessions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s := newPooledTestSession()
		conn, peer := stdnet.Pipe()
		defer peer.Close()
		s.conn = conn
		c.markSessionIdle(s)

		var calls int
		c.idleCleanup.Interval = time.Second
		c.idleCleanup.Execute = func() error {
			calls++
			return nil
		}
		if err := c.idleCleanup.Start(); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if calls != 1 {
			t.Errorf("cleanup ran %d times, want only the call from Start", calls)
		}
		if !s.isClosed() {
			t.Fatal("session is still open")
		}
		if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("peer read error = %v, want EOF", err)
		}
		if got, err := c.takeIdleSession(); got != nil || err != io.ErrClosedPipe {
			t.Errorf("takeIdleSession() = (%p, %v), want a closed client error", got, err)
		}
	})
}
