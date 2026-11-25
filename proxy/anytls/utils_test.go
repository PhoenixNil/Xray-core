package anytls

import (
	"io"
	"math"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestReadText(t *testing.T) {
	for _, length := range []int{0, buf.Size, buf.Size + 1, math.MaxUint16} {
		want := strings.Repeat("a", length)
		br := &buf.BufferedReader{Reader: buf.NewReader(strings.NewReader(want + "!"))}
		got, err := readText(br, length)
		if err != nil || got != want {
			t.Fatalf("length %d: got %d bytes, error %v", length, len(got), err)
		}
		if next, err := br.ReadByte(); err != nil || next != '!' {
			t.Fatalf("length %d: next byte = %q, error %v", length, next, err)
		}
	}
}

func TestReadTextTruncated(t *testing.T) {
	br := &buf.BufferedReader{Reader: buf.NewReader(strings.NewReader("abc"))}
	if got, err := readText(br, 4); got != "" || err != io.ErrUnexpectedEOF {
		t.Fatalf("readText() = (%q, %v), want empty text and unexpected EOF", got, err)
	}
}
