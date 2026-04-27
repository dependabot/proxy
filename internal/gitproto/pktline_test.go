package gitproto

import (
	"bytes"
	"testing"
)

func TestParsePktLine_Empty(t *testing.T) {
	pkts, ok := parsePktLine(nil)
	if !ok {
		t.Error("expected ok=true for empty input")
	}
	if len(pkts) != 0 {
		t.Fatalf("expected 0 packets, got %d", len(pkts))
	}
}

func TestParsePktLine_SpecialPackets(t *testing.T) {
	cases := map[string]pktType{
		"0000": pktFlush,
		"0001": pktDelim,
		"0002": pktResponseEnd,
	}
	for input, want := range cases {
		pkts, ok := parsePktLine([]byte(input))
		if !ok || len(pkts) != 1 || pkts[0].typ != want {
			t.Errorf("input %q: got %+v ok=%v, want type %d", input, pkts, ok, want)
		}
	}
}

func TestParsePktLine_DataPacket(t *testing.T) {
	// "000ahello\n" = length 0x000a (10), payload "hello\n"
	pkts, ok := parsePktLine([]byte("000ahello\n"))
	if !ok || len(pkts) != 1 || pkts[0].typ != pktData || string(pkts[0].payload) != "hello\n" {
		t.Errorf("got %+v ok=%v", pkts, ok)
	}
}

func TestParsePktLine_MalformedAndTruncated(t *testing.T) {
	// Bad hex prefix.
	if _, ok := parsePktLine([]byte("gggghi")); ok {
		t.Error("expected ok=false for malformed length prefix")
	}
	// Length claims 0x0020 but only 9 bytes available.
	if _, ok := parsePktLine([]byte("0020short")); ok {
		t.Error("expected ok=false for truncated packet")
	}
	// Length 3 is reserved; we treat as malformed.
	if _, ok := parsePktLine([]byte("00030000")); ok {
		t.Error("expected ok=false for reserved length 3")
	}
	// Less than 4 bytes.
	if _, ok := parsePktLine([]byte("ab")); ok {
		t.Error("expected ok=false for sub-prefix input")
	}
}

func TestParsePktLine_RealV1Body(t *testing.T) {
	// Realistic v1 upload-pack body from github.com/octocat/Hello-World
	input := "00a4want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d multi_ack_detailed no-done side-band-64k thin-pack no-progress ofs-delta deepen-since deepen-not agent=git/2.43.0\n" +
		"0032want b1b3f9723831141a31a1a7252a213e216ea76e56\n" +
		"0000" +
		"0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n" +
		"0009done\n"
	pkts, ok := parsePktLine([]byte(input))
	if !ok {
		t.Fatal("expected ok=true for well-formed v1 body")
	}
	wantTypes := []pktType{pktData, pktData, pktFlush, pktData, pktData}
	if len(pkts) != len(wantTypes) {
		t.Fatalf("got %d packets, want %d", len(pkts), len(wantTypes))
	}
	for i, want := range wantTypes {
		if pkts[i].typ != want {
			t.Errorf("packet %d: got type %d, want %d", i, pkts[i].typ, want)
		}
	}
}

func TestParsePktLine_RealV2Body(t *testing.T) {
	input := "0012command=fetch\n" +
		"0015agent=git/2.43.0\n" +
		"0001" +
		"000ddeepen 1\n" +
		"0032want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\n" +
		"0009done\n" +
		"0000"
	pkts, ok := parsePktLine([]byte(input))
	if !ok || len(pkts) != 7 {
		t.Fatalf("got %d packets ok=%v, want 7 ok=true", len(pkts), ok)
	}
	if pkts[2].typ != pktDelim || pkts[6].typ != pktFlush {
		t.Error("special packets misidentified")
	}
}

func TestEncodePktLine_RoundTrip(t *testing.T) {
	input := []byte("000ahello\n" + "0000" + "0001" + "000aworld\n" + "0002")
	pkts, ok := parsePktLine(input)
	if !ok {
		t.Fatal("parse failed on well-formed input")
	}
	if got := encodePktLine(pkts); !bytes.Equal(got, input) {
		t.Errorf("round-trip mismatch:\n  in:  %q\n  out: %q", input, got)
	}
}
