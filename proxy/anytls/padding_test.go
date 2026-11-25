package anytls

import (
	"crypto/md5"
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// The padding scheme specifies the total TLS plaintext length of each record.
// Every frame carries a 7-byte header, so any record built for a target size
// must budget for it. Getting this wrong changes the on-wire record sizes and
// breaks padding-fingerprint compatibility with sing-box / anytls-go / mihomo.
const frameHeaderLen = 7

func TestPureWasteRecordMatchesSchemeSize(t *testing.T) {
	for _, size := range []int32{8, 30, 100, 512, 1000, 8191} {
		f := &frame{cmd: cmdWaste, sid: 0, data: zeroPadding[:size-frameHeaderLen]}
		got := f.toMultiBuffer().Len()
		if got != size {
			t.Errorf("pure waste record for scheme size %d: got %d bytes on the wire, want %d", size, got, size)
		}
	}
}

func TestPaddedDataRecordMatchesSchemeSize(t *testing.T) {
	// remain is the length of the already-framed user data.
	for _, tc := range []struct{ size, remain int32 }{
		{100, 20}, {512, 64}, {1000, 993}, {1000, 500},
	} {
		pad := tc.size - tc.remain - frameHeaderLen
		if pad <= 0 {
			continue
		}
		wasteFrame := (&frame{cmd: cmdWaste, sid: 0, data: zeroPadding[:pad]}).toMultiBuffer()
		got := tc.remain + wasteFrame.Len()
		buf.ReleaseMulti(wasteFrame)
		if got != tc.size {
			t.Errorf("data+padding record (size=%d remain=%d): got %d, want %d", tc.size, tc.remain, got, tc.size)
		}
	}
}

func TestFrameHeaderIsSevenBytes(t *testing.T) {
	if got := newFrame(cmdPSH, 1).toMultiBuffer().Len(); got != frameHeaderLen {
		t.Errorf("empty frame: got %d bytes, want %d", got, frameHeaderLen)
	}
}

// The server rejects a session whose padding-md5 does not match what it expects,
// so the default scheme must hash to a stable, known value.
func TestDefaultPaddingSchemeMD5(t *testing.T) {
	s := getDefaultPaddingScheme()
	if s == nil {
		t.Fatal("default padding scheme failed to parse")
	}
	if s.stop != 8 {
		t.Errorf("stop: got %d, want 8", s.stop)
	}
	sum := md5.Sum(defaultPaddingScheme)
	if want := hex.EncodeToString(sum[:]); s.md5 != want {
		t.Errorf("md5: got %s, want %s", s.md5, want)
	}
}

func TestGenerateRecordPayloadSizesParsesCheckMark(t *testing.T) {
	s := getDefaultPaddingScheme()
	// pkt 2 is "400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000"
	sizes := s.GenerateRecordPayloadSizes(2)
	if len(sizes) != 9 {
		t.Fatalf("pkt 2: got %d entries, want 9", len(sizes))
	}
	marks := 0
	for i, v := range sizes {
		if v == CheckMark {
			marks++
			continue
		}
		if v <= frameHeaderLen {
			t.Errorf("pkt 2 entry %d: size %d is not larger than the frame header", i, v)
		}
	}
	if marks != 4 {
		t.Errorf("pkt 2: got %d check marks, want 4", marks)
	}
	// A packet index at or beyond stop has no scheme entry.
	if got := s.GenerateRecordPayloadSizes(s.stop); len(got) != 0 {
		t.Errorf("pkt %d (== stop): got %d entries, want 0", s.stop, len(got))
	}
}

// recordingWriter captures the size of every flushed TLS record.
type recordingWriter struct{ records []int32 }

func (w *recordingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := mb.Len(); n > 0 {
		w.records = append(w.records, n)
	}
	buf.ReleaseMulti(mb)
	return nil
}

// newTestSession wires a session to a recording writer with a fixed scheme.
func newTestSession(scheme string) (*session, *recordingWriter) {
	rec := &recordingWriter{}
	s := &session{isClient: true, bw: buf.NewBufferedWriter(rec)}
	s.fw = newFrameWriter(s.bw)
	s.paddingScheme = newPaddingScheme([]byte(scheme))
	return s, rec
}

// This is the end-to-end check: drive writePacketWithPadding and assert the
// bytes it actually emits match the sizes the scheme asks for.
func TestWritePacketWithPaddingEmitsSchemeSizes(t *testing.T) {
	// One tiny payload, then two pure-waste records. Fixed sizes, no ranges,
	// so the expected output is fully deterministic.
	s, rec := newTestSession("stop=8\n1=100-100,200-200,300-300")

	payload := (&frame{cmd: cmdPSH, sid: 1, data: []byte("hi")}).toMultiBuffer()
	payloadLen := payload.Len() // 7 header + 2 = 9

	if err := s.writePacketWithPadding(1, payload); err != nil {
		t.Fatalf("writePacketWithPadding: %v", err)
	}

	want := []int32{100, 200, 300}
	if len(rec.records) != len(want) {
		t.Fatalf("emitted %d records %v, want %d %v", len(rec.records), rec.records, len(want), want)
	}
	for i := range want {
		if rec.records[i] != want[i] {
			t.Errorf("record %d: emitted %d bytes, scheme asked for %d", i, rec.records[i], want[i])
		}
	}
	if total, wantTotal := sum(rec.records), int32(600); total != wantTotal {
		t.Errorf("total bytes on wire: %d, want %d (payload was %d)", total, wantTotal, payloadLen)
	}
}

func sum(v []int32) int32 {
	var t int32
	for _, x := range v {
		t += x
	}
	return t
}

// A scheme pushed by the server must be per-server state: every session created
// afterwards has to start with it, and padding0 must be recomputed from it.
// Keeping it only on the session means each new TLS connection re-emits the
// default fingerprint and forces the server to push the scheme again.
func TestPushedSchemeAppliesToSubsequentSessions(t *testing.T) {
	c := &Client{paddingScheme: getDefaultPaddingScheme()}
	c.authPadding = getPadding0Size(c.paddingScheme)

	defScheme, defPadding := c.currentPadding()
	if defPadding != 30 { // default scheme's "0=30-30"
		t.Fatalf("default padding0: got %d, want 30", defPadding)
	}

	// Server pushes a scheme with a different padding0 and stop value.
	pushed, err := parsePaddingScheme("stop=3\n0=77-77\n1=100-200\n2=300-400")
	if err != nil || pushed == nil {
		t.Fatalf("parsePaddingScheme: %v", err)
	}
	c.updatePaddingScheme(pushed)

	gotScheme, gotPadding := c.currentPadding()
	if gotScheme == defScheme {
		t.Error("scheme was not replaced on the Client")
	}
	if gotScheme.md5 != pushed.md5 {
		t.Errorf("scheme md5: got %s, want %s", gotScheme.md5, pushed.md5)
	}
	if gotScheme.stop != 3 {
		t.Errorf("stop: got %d, want 3", gotScheme.stop)
	}
	// padding0 must be re-derived, not left at the default.
	if gotPadding != 77 {
		t.Errorf("padding0 after push: got %d, want 77 (was %d)", gotPadding, defPadding)
	}
}
