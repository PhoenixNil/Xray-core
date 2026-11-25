package anytls

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type session struct {
	isClient bool
	conn     stat.Connection
	br       *buf.BufferedReader
	bw       *buf.BufferedWriter
	fw       *frameWriter

	writeMu sync.Mutex

	streamsMu sync.Mutex
	streams   map[uint32]*stream

	// peerVersion is written by readLoop and read by openStream on another
	// goroutine, so it must be accessed atomically.
	peerVersion atomic.Uint32
	errCh       chan error
	closed      atomic.Bool
	seq         uint64

	server           *Server
	dispatcher       routing.Dispatcher
	handshakeDone    bool
	clientPaddingMD5 string

	client       *Client
	nextSID      atomic.Uint32
	pktCounter   atomic.Uint32
	settingsSent bool

	schemeMu      sync.RWMutex
	paddingScheme *paddingScheme

	synAckMu sync.Mutex
	synAckCh map[uint32]chan error

	activeStreams atomic.Int32
	idleSinceNano atomic.Int64
	inIdlePool    atomic.Bool
	dieHook       func()
}

func (s *session) handlePSH(ctx context.Context, st *stream, br *buf.BufferedReader, length int) error {
	if st == nil || st.link == nil {
		return errors.New("anytls: received PSH for unknown stream")
	}
	body, err := readMultiBufferExact(br, length)
	if err != nil {
		buf.ReleaseMulti(body)
		return err
	}

	if err := st.link.Writer.WriteMultiBuffer(body); err != nil {
		// Only the local side of this stream is gone (e.g. the app closed the
		// connection mid-download); the session is still healthy. finishStream
		// closes the link, so the stream's own pump exits and sends the FIN.
		s.finishStream(st.sid, err)
	}
	return nil
}

func (s *session) handleNewStream(ctx context.Context, st *stream, br *buf.BufferedReader) error {
	dest, err := readDestination(socksAddrParser, br, net.Network_TCP)
	if err != nil {
		return errors.New("anytls: invalid destination address in SYN").Base(err)
	}

	// Check for UDP-over-TCP v2 magic domain in a new stream request.
	if strings.Contains(dest.Address.String(), "udp-over-tcp.arpa") {
		st.isUDP = true
		if err := s.sendFrame(newFrame(cmdSYNACK, st.sid)); err != nil {
			errors.LogWarning(ctx, "anytls: UDP SYNACK send error, streamId=", st.sid, " err=", err)
			return err
		}
		return nil
	}

	l, err := s.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		errors.LogWarning(ctx, "anytls: new stream dispatcher error, streamId=", st.sid, " err=", err)
		return nil
	}
	st.link = l

	if err := s.sendFrame(newFrame(cmdSYNACK, st.sid)); err != nil {
		errors.LogWarning(ctx, "anytls: new stream SYNACK send error, streamId=", st.sid, " err=", err)
		return err
	}

	go s.pumpDownlink(ctx, st.sid, l, nil, false)
	return nil
}

func (s *session) handleFirstUDPFrame(ctx context.Context, st *stream, br *buf.BufferedReader, length int) error {
	if st.link == nil {
		// The request must be parsed out of this frame's body rather than
		// straight off br: a client is free to pack the request and the first
		// datagrams into a single PSH frame, and reading past the body would
		// make readLoop take payload bytes for the next frame header.
		body := make([]byte, length)
		if _, err := io.ReadFull(br, body); err != nil {
			return err
		}
		reader := bytes.NewReader(body)

		request, err := readUoTRequest(reader)
		if err != nil {
			errors.LogWarning(ctx, "anytls: UDP failed to parse request:", err)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.finishStream(st.sid, nil)
			return nil
		}
		requestDest := request.Destination

		link, err := s.dispatcher.Dispatch(ctx, requestDest)
		if err != nil {
			errors.LogWarning(ctx, "anytls: UDP dispatcher error, streamId=", st.sid, " err=", err)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.finishStream(st.sid, nil)
			return nil
		}

		// Connect mode drops the per-packet address, so every datagram on this
		// stream implicitly targets the request destination.
		var connectDest *net.Destination
		if request.IsConnect {
			connectDest = &requestDest
		}

		// Datagrams need udp-over-tcp framing in both directions: decode on the
		// uplink here, encode on the downlink in pumpDownlink. Writing PSH bodies
		// straight to the dispatcher would send the address/length header as part
		// of the UDP payload, and replying with bare payloads would desynchronise
		// the client's decoder.
		//
		// Routing follows the destination in the UoT request. Datagrams addressed
		// elsewhere still reach the right peer, because the dispatched link carries
		// each buffer's own destination in buf.Buffer.UDP.
		st.link = &transport.Link{
			Reader: link.Reader,
			Writer: &uotReassembler{writer: link.Writer, connectDest: connectDest},
		}
		st.udpTarget = &requestDest

		go s.pumpDownlink(ctx, st.sid, link, &requestDest, request.IsConnect)

		// Datagrams the client packed behind the request in this same frame.
		if reader.Len() > 0 {
			rest := buf.MergeBytes(nil, body[len(body)-reader.Len():])
			if err := st.link.Writer.WriteMultiBuffer(rest); err != nil {
				return err
			}
		}
		return nil
	}

	return nil
}

// pumpDownlink relays the dispatched link back to the peer. A non-nil udpTarget
// marks the stream as udp-over-tcp, so every datagram gets framed on the way out.
func (s *session) pumpDownlink(ctx context.Context, sid uint32, link *transport.Link, udpTarget *net.Destination, connect bool) {
	defer func() {
		s.streamsMu.Lock()
		st := s.streams[sid]
		delete(s.streams, sid)
		s.streamsMu.Unlock()
		if st != nil && st.link != nil {
			common.Close(st.link.Writer)
			common.Close(st.link.Reader)
		}
		if !s.isClosed() {
			_ = s.sendFrame(newFrame(cmdFIN, sid))
		}
	}()

	for {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		if udpTarget != nil {
			mb, err = encodeUoTMulti(mb, *udpTarget, connect)
			if err != nil {
				errors.LogWarning(ctx, "anytls: failed to frame UoT packet, streamId=", sid, " err=", err)
				return
			}
		}

		if err := s.sendStreamData(sid, mb, 0); err != nil {
			return
		}
	}
}

func (s *session) isClosed() bool {
	return s.closed.Load()
}

func (s *session) close(err error) {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if err != nil {
		select {
		case s.errCh <- err:
		default:
		}
	}
	_ = s.conn.Close()

	s.streamsMu.Lock()
	streams := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*stream)
	s.streamsMu.Unlock()

	for _, st := range streams {
		st.close(err)
	}
	if s.dieHook != nil {
		s.dieHook()
	}
}

func (s *session) finishStream(sid uint32, err error) {
	s.streamsMu.Lock()
	st := s.streams[sid]
	if st != nil {
		delete(s.streams, sid)
	}
	s.streamsMu.Unlock()

	if st == nil {
		return
	}

	if s.client != nil {
		s.activeStreams.Add(-1)
	}
	st.close(err)
}

// discardStream drops a stream that never finished opening. Unlike finishStream
// it does not close the link, because the caller still owns it and may retry the
// request on a fresh session.
func (s *session) discardStream(sid uint32) {
	s.streamsMu.Lock()
	st := s.streams[sid]
	if st != nil {
		delete(s.streams, sid)
	}
	s.streamsMu.Unlock()

	if st == nil {
		return
	}
	if s.client != nil {
		s.activeStreams.Add(-1)
	}
	st.detach()
}

func (s *session) sendFrame(f *frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.fw.writeFrame(f); err != nil {
		return err
	}
	return s.fw.flush()
}

// writePSH consumes body and submits the entire unpadded frame in one Write.
func (s *session) writePSH(sid uint32, body buf.MultiBuffer) error {
	payloadLen := body.Len()
	frameLen := 7 + payloadLen
	packet := bytespool.Alloc(frameLen)[:frameLen]
	defer bytespool.Free(packet)
	packet[0] = cmdPSH
	binary.BigEndian.PutUint32(packet[1:5], sid)
	binary.BigEndian.PutUint16(packet[5:7], uint16(payloadLen))
	buf.SplitBytes(body, packet[7:])

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	n, err := s.conn.Write(packet)
	if err == nil && n != len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func (s *session) sendStreamData(sid uint32, data buf.MultiBuffer, packetIndex uint32) error {
	defer buf.ReleaseMulti(data)
	for !data.IsEmpty() {
		var chunk buf.MultiBuffer
		data, chunk = buf.SplitSize(data, maxFramePayload)
		if packetIndex > 0 {
			b := buf.New()
			p := b.Extend(7)
			p[0] = cmdPSH
			binary.BigEndian.PutUint32(p[1:5], sid)
			binary.BigEndian.PutUint16(p[5:7], uint16(chunk.Len()))
			merge, _ := buf.MergeMulti(buf.MultiBuffer{b}, chunk)
			s.writeMu.Lock()
			err := s.writePacketWithPadding(packetIndex, merge)
			s.writeMu.Unlock()
			if err != nil {
				return err
			}
		} else if err := s.writePSH(sid, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) readLoop(ctx context.Context) error {
	var head [7]byte
	for {
		_, err := io.ReadFull(s.br, head[:])
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return err
		}

		cmd := head[0]
		sid := binary.BigEndian.Uint32(head[1:5])
		length := int(binary.BigEndian.Uint16(head[5:7]))
		//errors.LogDebug(ctx, "anytls: received frame cmd=", cmd, " streamId=", sid, " length=", length)
		switch cmd {
		case cmdWaste:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
		case cmdSettings:
			if s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected cmdSettings from server")
			}
			text, err := readText(s.br, length)
			if err != nil {
				return err
			}
			if s.handshakeDone {
				continue
			}
			if text != "" {
				lines := strings.Split(text, "\n")
				for _, line := range lines {
					if line == "" {
						continue
					}
					kv := strings.SplitN(line, "=", 2)
					if len(kv) != 2 {
						continue
					}
					switch kv[0] {
					case "v":
						if v, err := strconv.Atoi(kv[1]); err == nil {
							s.peerVersion.Store(uint32(v))
						}
					case "padding-md5":
						s.clientPaddingMD5 = strings.ToLower(kv[1])
					}
				}
			}
			if err := s.sendFrame(&frame{cmd: cmdServerSettings, sid: 0, data: []byte("v=2")}); err != nil {
				return err
			}
			if s.server != nil && s.server.paddingScheme != "" && s.clientPaddingMD5 != "" {
				sum := md5.Sum([]byte(s.server.paddingScheme))
				if strings.ToLower(hex.EncodeToString(sum[:])) != s.clientPaddingMD5 {
					if err := s.sendFrame(&frame{cmd: cmdUpdatePaddingScheme, sid: 0, data: []byte(s.server.paddingScheme)}); err != nil {
						return err
					}
				}
			}
			s.handshakeDone = true
		case cmdHeartRequest:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			if err := s.sendFrame(newFrame(cmdHeartResponse, 0)); err != nil {
				return err
			}
		case cmdHeartResponse:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
		case cmdSYN:
			if s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected SYN from server")
			} else {
				if !s.handshakeDone {
					alert := newFrame(cmdAlert, 0)
					alert.data = []byte("client did not send its settings")
					_ = s.sendFrame(alert)
					return errors.New("anytls: client did not send its settings")
				}
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
					errors.LogWarning(ctx, "anytls: unexpected data in SYN, streamId=", sid)
					if err := s.sendFrame(&frame{cmd: cmdSYNACK, sid: sid, data: []byte("unexpected syn body")}); err != nil {
						return err
					}
					continue
				}
				s.streamsMu.Lock()
				if _, ok := s.streams[sid]; !ok {
					s.streams[sid] = &stream{sid: sid}
				}
				s.streamsMu.Unlock()
			}
		case cmdPSH:
			if length <= 0 {
				err := errors.New("anytls: PSH frame with empty payload, streamId=", sid)
				s.finishStream(sid, err)
				return err
			}
			s.streamsMu.Lock()
			st := s.streams[sid]
			s.streamsMu.Unlock()
			if st == nil {
				// Late data for a stream this side already closed: the peer sent
				// it before our FIN reached it. Drop it and keep reading; leaving
				// the loop here would park the session in the idle pool with no
				// reader, and the next stream on it would stall until the SYNACK
				// timeout.
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
				continue
			} else if st.isUDP && st.link == nil {
				if err := s.handleFirstUDPFrame(ctx, st, s.br, length); err != nil {
					return err
				}
				continue
			} else if st.link == nil {
				s.handleNewStream(ctx, st, s.br)
				continue
			}
			if err := s.handlePSH(ctx, st, s.br, length); err != nil {
				return err
			}
		case cmdFIN:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			s.finishStream(sid, nil)
		case cmdSYNACK:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected SYNACK from client")
			}
			s.synAckMu.Lock()
			ch := s.synAckCh[sid]
			s.synAckMu.Unlock()
			if length == 0 {
				if ch != nil {
					ch <- nil
				}
			} else {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				errors.LogWarning(ctx, "anytls: stream handshake rejected, streamId=", sid, " err=", bodyText)
				s.finishStream(sid, errors.New(bodyText))
				if ch != nil {
					ch <- errors.New(bodyText)
				}
			}
		case cmdServerSettings:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected ServerSettings from client")
			}
			if length > 0 {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				lines := strings.Split(bodyText, "\n")
				for _, line := range lines {
					kv := strings.SplitN(line, "=", 2)
					if len(kv) != 2 {
						continue
					}
					if kv[0] != "v" {
						continue
					}
					if v, err := strconv.Atoi(kv[1]); err == nil {
						s.peerVersion.Store(uint32(v))
					}
				}
			} else {
				errors.LogWarning(ctx, "anytls: empty ServerSettings from server")
			}
		case cmdUpdatePaddingScheme:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected UpdatePaddingScheme from client")
			}
			if length > 0 {
				bodyText, err := readText(s.br, length)
				if err != nil {
					return err
				}
				scheme, perr := parsePaddingScheme(bodyText)
				if perr == nil && scheme != nil {
					s.schemeMu.Lock()
					s.paddingScheme = scheme
					s.schemeMu.Unlock()
					// Persist it per-server, so every subsequent session starts
					// with this scheme instead of falling back to the default
					// and making the server push it again on each connection.
					s.client.updatePaddingScheme(scheme)
				}
			} else {
				errors.LogWarning(ctx, "anytls: empty UpdatePaddingScheme from server")
			}
		case cmdAlert:
			if !s.isClient {
				if length > 0 {
					if err := discardBytes(s.br, length); err != nil {
						return err
					}
				}
				return errors.New("anytls: unexpected Alert from client")
			}
			var bodyText string
			if length > 0 {
				bodyText, err = readText(s.br, length)
				if err != nil {
					return err
				}
			}
			alertText := "anytls: server alert"
			if bodyText != "" {
				alertText += ": " + bodyText
			}
			return errors.New(alertText)
		default:
			if length > 0 {
				if err := discardBytes(s.br, length); err != nil {
					return err
				}
			}
			errors.LogWarning(ctx, "anytls: unknown cmd=", cmd, " streamId=", sid)
			return errors.New("anytls: unknown cmd")
		}
	}
}
