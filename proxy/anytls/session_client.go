package anytls

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

// zeroPadding backs every cmdWaste frame. The scheme check below rejects any size
// >= len(zeroPadding), so it is always large enough. Sharing one read-only zeroed
// array avoids allocating (and leaking) a pooled buffer per padded packet, and
// keeps stale pool memory from being sent as padding.
var zeroPadding [8192]byte

// writeAndFlush writes mb and flushes. bw.WriteMultiBuffer takes ownership of mb
// and releases it on both the success and error paths, so callers must not.
func (s *session) writeAndFlush(mb buf.MultiBuffer) error {
	if err := s.fw.bw.WriteMultiBuffer(mb); err != nil {
		return err
	}
	return s.fw.flush()
}

func (s *session) writePacketWithPadding(packetIndex uint32, frames buf.MultiBuffer) error {
	if frames.Len() == 0 {
		return nil
	}
	s.schemeMu.RLock()
	scheme := s.paddingScheme
	s.schemeMu.RUnlock()
	if scheme == nil || packetIndex >= scheme.stop {
		return s.writeAndFlush(frames)
	}
	pktSizes := scheme.GenerateRecordPayloadSizes(packetIndex)
	if len(pktSizes) == 0 {
		return s.writeAndFlush(frames)
	}

	b := frames
	for _, targetsize := range pktSizes {
		size := int32(targetsize)
		remain := b.Len()
		if size == CheckMark {
			if b.IsEmpty() {
				break
			}
			continue
		}
		if size <= 7 || size >= int32(len(zeroPadding)) {
			buf.ReleaseMulti(b)
			return errors.New("anytls: invalid padding scheme")
		}

		if remain > size {
			var data buf.MultiBuffer
			b, data = buf.SplitSize(b, size)
			if err := s.writeAndFlush(data); err != nil {
				buf.ReleaseMulti(b)
				return err
			}
		} else if remain > 0 {
			toSend := b
			if pad := size - remain - 7; pad > 0 {
				paddingFrame := (&frame{cmd: cmdWaste, sid: 0, data: zeroPadding[:pad]}).toMultiBuffer()
				toSend, _ = buf.MergeMulti(b, paddingFrame)
			}
			b = nil
			if err := s.writeAndFlush(toSend); err != nil {
				return err
			}
		} else {
			// Scheme sizes are total TLS plaintext length, and toMultiBuffer
			// prepends a 7-byte frame header, so the body must be size-7.
			// (size > 7 is guaranteed by the check above.)
			padding := (&frame{cmd: cmdWaste, sid: 0, data: zeroPadding[:size-7]}).toMultiBuffer()
			if err := s.writeAndFlush(padding); err != nil {
				return err
			}
		}
	}
	if !b.IsEmpty() {
		return s.writeAndFlush(b)
	}

	return nil
}

func (s *session) openStream(ctx context.Context, target net.Destination, link *transport.Link) (*stream, error) {
	if s.isClosed() {
		return nil, errors.New("anytls: session closed")
	}

	actualDest := target
	if target.Network == net.Network_UDP {
		actualDest = net.Destination{
			Network: net.Network_TCP,
			Address: net.DomainAddress(uotMagicAddress),
			Port:    0,
		}
	}

	sid := s.nextSID.Add(1) - 1
	st := newStream(sid, link)
	// The hook has to be in place before the stream becomes reachable from
	// readLoop below. A FIN can land the moment the SYN is on the wire, and a
	// hook assigned after openStream returns would simply never run: the stream
	// close still decrements activeStreams, but the session is never marked
	// idle, so it can neither be reused by takeIdleSession nor timed out by
	// cleanupIdleSessions — both only look at idleSessions. Assigning it here
	// also keeps the write ordered before readLoop's read by streamsMu.
	if c := s.client; c != nil {
		st.dieHook = func() {
			if s.isClosed() || s.activeStreams.Load() != 0 {
				return
			}
			c.markSessionIdle(s)
		}
	}
	if target.Network == net.Network_UDP {
		// Datagrams need udp-over-tcp framing in both directions: encode on the
		// uplink in pumpUplink, decode on the downlink here.
		st.isUDP = true
		udpTarget := target
		st.udpTarget = &udpTarget
		st.link = &transport.Link{
			Reader: link.Reader,
			Writer: &uotReassembler{writer: link.Writer},
		}
	}
	waitForSynAck := sid >= 2 && s.peerVersion.Load() >= 2
	s.streamsMu.Lock()
	s.streams[st.sid] = st
	s.streamsMu.Unlock()
	s.activeStreams.Add(1)
	s.inIdlePool.Store(false)

	var ch chan error
	if waitForSynAck {
		ch = make(chan error, 1)
		s.synAckMu.Lock()
		s.synAckCh[sid] = ch
		s.synAckMu.Unlock()
		defer func() {
			s.synAckMu.Lock()
			delete(s.synAckCh, sid)
			s.synAckMu.Unlock()
		}()
	}

	var frames buf.MultiBuffer
	if !s.settingsSent {
		s.schemeMu.RLock()
		md5Value := s.paddingScheme.md5
		s.schemeMu.RUnlock()
		frames = append(frames, (&frame{cmd: cmdSettings, sid: 0, data: []byte("v=2\nclient=xray\npadding-md5=" + md5Value)}).toMultiBuffer()...)
		s.settingsSent = true
	}
	addrBuf := buf.New()
	if err := writeDestination(socksAddrParser, addrBuf, actualDest); err != nil {
		addrBuf.Release()
		s.discardStream(sid)
		return nil, errors.New("anytls: write socks addr failed").Base(err)
	}
	frames = append(frames, newFrame(cmdSYN, sid).toMultiBuffer()...)
	frames = append(frames, (&frame{cmd: cmdPSH, sid: sid}).toMultiBufferWithBody(addrBuf)...)

	s.writeMu.Lock()
	writeErr := s.writePacketWithPadding(s.pktCounter.Add(1)-1, frames)
	s.writeMu.Unlock()
	if writeErr != nil {
		s.discardStream(sid)
		return nil, errors.New("anytls: send session open packet failed").Base(writeErr)
	}

	if waitForSynAck {
		select {
		case serr := <-ch:
			if serr != nil {
				s.discardStream(sid)
				return nil, errors.New("anytls: SYN rejected").Base(serr)
			}
		case sessErr := <-s.errCh:
			s.discardStream(sid)
			return nil, sessErr
		case <-time.After(3 * time.Second):
			// A pooled session the server already dropped: detach our stream
			// first so session.close does not tear down the caller's link,
			// letting Process retry on a fresh session.
			timeoutErr := errors.New("anytls: SYNACK timeout")
			s.discardStream(sid)
			s.close(timeoutErr)
			return nil, timeoutErr
		case <-ctx.Done():
			s.discardStream(sid)
			return nil, ctx.Err()
		}
	}

	if target.Network == net.Network_UDP {
		reqBuf := buf.New()
		// The address keeps its own family: an IP goes out as ATYP=1/4, never as a
		// domain (ATYP=3), which would make the server treat e.g. "8.8.8.8" as a
		// domain and miss every IP-based routing rule.
		err := writeUoTRequest(reqBuf, uotRequest{Destination: target})
		if err != nil {
			reqBuf.Release()
			s.discardStream(sid)
			return nil, errors.New("anytls: write UoT request failed").Base(err)
		}
		UDPPSHframe := (&frame{cmd: cmdPSH, sid: sid}).toMultiBufferWithBody(reqBuf)

		s.writeMu.Lock()
		err = s.writePacketWithPadding(s.pktCounter.Add(1)-1, UDPPSHframe)
		s.writeMu.Unlock()

		if err != nil {
			s.discardStream(sid)
			return nil, errors.New("anytls: send UoT request failed").Base(err)
		}
	}

	return st, nil
}

func (st *stream) pumpUplink(s *session) {
	defer func() {
		_ = s.sendFrame(newFrame(cmdFIN, st.sid))
		s.finishStream(st.sid, nil)
	}()
	for {
		mb, err := st.link.Reader.ReadMultiBuffer()
		if err != nil {
			break
		}
		if st.isUDP {
			var target net.Destination
			if st.udpTarget != nil {
				target = *st.udpTarget
			}
			mb, err = encodeUoTMulti(mb, target, false)
			if err != nil {
				errors.LogWarning(context.Background(), "anytls: failed to frame UoT packet: ", err)
				s.close(err)
				return
			}
		}
		var pktIndex uint32
		s.schemeMu.RLock()
		scheme := s.paddingScheme
		s.schemeMu.RUnlock()

		if scheme != nil && s.pktCounter.Load() < scheme.stop {
			pktIndex = s.pktCounter.Add(1) - 1
		} else {
			pktIndex = 0
		}

		if sendErr := s.sendStreamData(st.sid, mb, pktIndex); sendErr != nil {
			errors.LogDebug(context.Background(), "anytls: writePacketWithPadding error=", sendErr)
			_ = s.sendFrame(newFrame(cmdFIN, st.sid))
			s.close(sendErr)
			return
		}

	}
}
