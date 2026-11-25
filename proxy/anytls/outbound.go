package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	sessionctx "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	defaultIdleSessionCheckInterval = 30 * time.Second
	// Matches sing-box's default. Kept short on purpose: this client sends no
	// heartbeats, so a pooled session must be dropped before the server's own
	// idle timeout fires, otherwise reuse hits a SYNACK timeout.
	defaultIdleSessionTimeout = 30 * time.Second
	defaultMinIdleSession     = 0
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager

	idleCleanup        task.Periodic
	idleSessionTimeout time.Duration
	minIdleSession     int

	// The padding scheme is per-server state, not per-session: a scheme pushed
	// by the server via cmdUpdatePaddingScheme must apply to every subsequent
	// session with that server, otherwise each new connection re-emits the
	// default padding fingerprint and forces the server to push it again.
	// authPadding (the padding0 length) is derived from it and is recomputed
	// whenever it changes.
	schemeMu      sync.RWMutex
	paddingScheme *paddingScheme
	authPadding   uint16
	authHash      [32]byte

	sessionsMu   sync.Mutex
	sessions     map[uint64]*session // nil once the client is closed
	idleSessions []uint64
	sessionSeq   atomic.Uint64
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config == nil || config.Server == nil {
		return nil, errors.New("anytls: no server specified")
	}

	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	if server.User == nil {
		return nil, errors.New("anytls: no user specified")
	}
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok {
		return nil, errors.New("anytls: invalid account type")
	}

	v := core.MustFromContext(ctx)
	client := &Client{
		server:             server,
		policyManager:      v.GetFeature(policy.ManagerType()).(policy.Manager),
		idleSessionTimeout: defaultIdleSessionTimeout,
		minIdleSession:     defaultMinIdleSession,
		paddingScheme:      getDefaultPaddingScheme(),
		authHash:           sha256.Sum256([]byte(account.Password)),
		sessions:           make(map[uint64]*session),
	}
	client.authPadding = getPadding0Size(client.paddingScheme)
	client.idleCleanup.Interval = defaultIdleSessionCheckInterval
	if value := config.GetIdleSessionCheckInterval(); value > 0 {
		client.idleCleanup.Interval = time.Duration(value) * time.Second
	}
	if value := config.GetIdleSessionTimeout(); value > 0 {
		client.idleSessionTimeout = time.Duration(value) * time.Second
	}
	client.minIdleSession = int(config.GetMinIdleSession())
	client.idleCleanup.Execute = client.cleanupIdleSessions
	if err := client.idleCleanup.Start(); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) Close() error {
	err := c.idleCleanup.Close()
	c.sessionsMu.Lock()
	sessions := c.sessions
	c.sessions = nil
	c.idleSessions = nil
	c.sessionsMu.Unlock()

	// Closing a session calls its dieHook, which takes sessionsMu.
	for _, sess := range sessions {
		sess.close(io.ErrClosedPipe)
	}
	return err
}

// currentPadding returns the scheme currently in effect for this server along
// with the padding0 length derived from it.
func (c *Client) currentPadding() (*paddingScheme, uint16) {
	c.schemeMu.RLock()
	defer c.schemeMu.RUnlock()
	return c.paddingScheme, c.authPadding
}

// updatePaddingScheme stores a scheme pushed by the server so that every
// subsequent session starts with it.
func (c *Client) updatePaddingScheme(scheme *paddingScheme) {
	if scheme == nil {
		return
	}
	c.schemeMu.Lock()
	c.paddingScheme = scheme
	c.authPadding = getPadding0Size(scheme)
	c.schemeMu.Unlock()
}

// takeIdleSession pops the most recently idled live session from the pool.
func (c *Client) takeIdleSession() (*session, error) {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	if c.sessions == nil {
		return nil, io.ErrClosedPipe
	}

	for len(c.idleSessions) > 0 {
		last := len(c.idleSessions) - 1
		seq := c.idleSessions[last]
		c.idleSessions = c.idleSessions[:last]
		sess := c.sessions[seq]
		if sess == nil {
			continue
		}
		sess.inIdlePool.Store(false)
		if sess.isClosed() {
			continue
		}
		return sess, nil
	}
	return nil, nil
}

// newSession dials the server and completes anytls authentication.
func (c *Client) newSession(ctx context.Context, dialer internet.Dialer, dest net.Destination) (*session, error) {
	seq := c.sessionSeq.Add(1)
	scheme, authPadding := c.currentPadding()
	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, dest)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return nil, errors.New("anytls: failed to establish connection").Base(err)
	}

	sess := &session{
		client:        c,
		isClient:      true,
		conn:          conn,
		br:            &buf.BufferedReader{Reader: buf.NewReader(conn)},
		bw:            buf.NewBufferedWriter(buf.NewWriter(conn)),
		paddingScheme: scheme,
		streams:       make(map[uint32]*stream),
		synAckCh:      make(map[uint32]chan error),
		errCh:         make(chan error, 1),
		seq:           seq,
	}
	sess.fw = newFrameWriter(sess.bw)
	sess.nextSID.Store(1)
	sess.pktCounter.Store(1)
	sess.peerVersion.Store(1)
	sess.dieHook = func() {
		c.sessionsMu.Lock()
		delete(c.sessions, sess.seq)
		c.sessionsMu.Unlock()
	}
	c.sessionsMu.Lock()
	if c.sessions == nil {
		c.sessionsMu.Unlock()
		conn.Close()
		return nil, io.ErrClosedPipe
	}
	c.sessions[seq] = sess
	c.sessionsMu.Unlock()

	// The protocol requires sha256(password) | padding0Len | padding0 to be sent
	// as a single TLS write; splitting it produces a distinctive 34-byte record
	// that defeats the purpose of padding0. make() also zeroes the padding, so
	// no stale pool memory leaks into it.
	auth := make([]byte, 34+int(authPadding))
	copy(auth[:32], c.authHash[:])
	binary.BigEndian.PutUint16(auth[32:34], authPadding)
	if _, err := conn.Write(auth); err != nil {
		sess.close(err)
		return nil, errors.New("anytls: write auth failed").Base(err)
	}
	errors.LogDebug(ctx, "anytls: new session created, seq=", seq)

	go func() {
		if err := sess.readLoop(ctx); err != nil && !sess.isClosed() {
			sess.close(err)
		}
	}()
	return sess, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := sessionctx.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "anytls"
	ob.CanSpliceCopy = 3
	destination := ob.Target
	dest := c.server.Destination

	// A pooled session may have been dropped by the server while it sat idle
	// (this client sends no heartbeats), which only surfaces as a SYNACK
	// timeout when we try to reuse it. Fall back to a fresh session once.
	var sess *session
	var stream *stream
	for attempt := 0; ; attempt++ {
		var err error
		sess, err = c.takeIdleSession()
		if err != nil {
			return err
		}
		reused := sess != nil
		if !reused {
			sess, err = c.newSession(ctx, dialer, dest)
			if err != nil {
				return err
			}
		}

		stream, err = sess.openStream(ctx, destination, link)
		if err == nil {
			break
		}
		sess.close(err)
		if !reused || attempt >= 1 {
			return errors.New("anytls: failed to open stream").Base(err)
		}
		errors.LogDebug(ctx, "anytls: pooled session was stale, retrying on a new session: ", err)
	}

	// openStream already installed stream.dieHook; doing it here would race with
	// a FIN that arrives before this line runs.
	go stream.pumpUplink(sess)

	select {
	case <-stream.done:
		return stream.result()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) markSessionIdle(sess *session) {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	if c.sessions == nil || sess == nil || sess.isClosed() {
		return
	}
	if !sess.inIdlePool.CompareAndSwap(false, true) {
		return
	}
	sess.idleSinceNano.Store(time.Now().UnixNano())
	c.idleSessions = append(c.idleSessions, sess.seq)
}

func (c *Client) cleanupIdleSessions() error {
	now := time.Now()
	var toClose []*session

	c.sessionsMu.Lock()
	validCount := 0
	for _, seq := range c.idleSessions {
		sess := c.sessions[seq]
		if sess == nil || sess.isClosed() || !sess.inIdlePool.Load() {
			continue
		}
		c.idleSessions[validCount] = seq
		validCount++
	}
	c.idleSessions = c.idleSessions[:validCount]

	keepFrom := validCount - c.minIdleSession
	if keepFrom < 0 {
		keepFrom = 0
	}

	keptCount := 0
	for idx, seq := range c.idleSessions {
		sess := c.sessions[seq]
		if sess == nil {
			continue
		}
		if idx >= keepFrom {
			c.idleSessions[keptCount] = seq
			keptCount++
			continue
		}
		idleSinceNano := sess.idleSinceNano.Load()
		if idleSinceNano == 0 || now.Sub(time.Unix(0, idleSinceNano)) <= c.idleSessionTimeout {
			c.idleSessions[keptCount] = seq
			keptCount++
			continue
		}
		sess.inIdlePool.Store(false)
		toClose = append(toClose, sess)
	}
	c.idleSessions = c.idleSessions[:keptCount]
	c.sessionsMu.Unlock()

	for _, sess := range toClose {
		sess.close(nil)
	}
	return nil
}
