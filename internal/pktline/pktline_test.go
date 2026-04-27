package pktline

import (
	"bytes"
	"testing"
)

func TestParseFlush(t *testing.T) {
	packets := Parse([]byte("0000"))
	if len(packets) != 1 || packets[0].Type != Flush {
		t.Fatal("expected single Flush packet")
	}
}

func TestParseDelim(t *testing.T) {
	packets := Parse([]byte("0001"))
	if len(packets) != 1 || packets[0].Type != Delim {
		t.Fatal("expected single Delim packet")
	}
}

func TestParseResponseEnd(t *testing.T) {
	packets := Parse([]byte("0002"))
	if len(packets) != 1 || packets[0].Type != ResponseEnd {
		t.Fatal("expected single ResponseEnd packet")
	}
}

func TestParseDataPacket(t *testing.T) {
	// "000ahello\n" = length 10 (0x000a), payload "hello\n"
	packets := Parse([]byte("000ahello\n"))
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].Type != Data {
		t.Fatal("expected Data packet")
	}
	if string(packets[0].Payload) != "hello\n" {
		t.Fatalf("expected payload %q, got %q", "hello\n", string(packets[0].Payload))
	}
}

func TestParseMultiplePackets(t *testing.T) {
	// Two data packets + flush
	input := "000ahello\n" + "000aworld\n" + "0000"
	packets := Parse([]byte(input))
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}
	if packets[0].Type != Data || string(packets[0].Payload) != "hello\n" {
		t.Error("first packet wrong")
	}
	if packets[1].Type != Data || string(packets[1].Payload) != "world\n" {
		t.Error("second packet wrong")
	}
	if packets[2].Type != Flush {
		t.Error("third packet should be Flush")
	}
}

func TestParseMalformedLength(t *testing.T) {
	// "gggg" is not valid hex — should return as raw data
	packets := Parse([]byte("gggghello"))
	if len(packets) != 1 || packets[0].Type != Data {
		t.Fatal("expected single raw Data packet for malformed input")
	}
	if string(packets[0].Payload) != "gggghello" {
		t.Fatalf("expected full input as payload, got %q", string(packets[0].Payload))
	}
}

func TestParseTruncatedPacket(t *testing.T) {
	// Claims length 0x0020 (32 bytes) but only has 10 bytes total
	packets := Parse([]byte("0020short"))
	if len(packets) != 1 || packets[0].Type != Data {
		t.Fatal("expected single raw Data packet for truncated input")
	}
}

func TestParseRealV1Body(t *testing.T) {
	// Real protocol v1 upload-pack body captured from git clone of octocat/Hello-World
	input := "00a4want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d multi_ack_detailed no-done side-band-64k thin-pack no-progress ofs-delta deepen-since deepen-not agent=git/2.43.0\n" +
		"0032want b1b3f9723831141a31a1a7252a213e216ea76e56\n" +
		"0000" +
		"0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n" +
		"0009done\n"
	packets := Parse([]byte(input))
	if len(packets) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(packets))
	}
	if packets[0].Type != Data {
		t.Error("packet 0 should be Data (want with caps)")
	}
	if packets[1].Type != Data {
		t.Error("packet 1 should be Data (want)")
	}
	if packets[2].Type != Flush {
		t.Error("packet 2 should be Flush")
	}
	if packets[3].Type != Data {
		t.Error("packet 3 should be Data (have)")
	}
	if packets[4].Type != Data {
		t.Error("packet 4 should be Data (done)")
	}
}

func TestParseRealV2Body(t *testing.T) {
	// Real protocol v2 fetch command
	input := "0012command=fetch\n" +
		"0015agent=git/2.43.0\n" +
		"0001" +
		"000ddeepen 1\n" +
		"0032want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\n" +
		"0009done\n" +
		"0000"
	packets := Parse([]byte(input))
	if len(packets) != 7 {
		t.Fatalf("expected 7 packets, got %d", len(packets))
	}
	if packets[0].Type != Data || string(packets[0].Payload) != "command=fetch\n" {
		t.Error("packet 0 should be command=fetch")
	}
	if packets[1].Type != Data || string(packets[1].Payload) != "agent=git/2.43.0\n" {
		t.Error("packet 1 should be agent=")
	}
	if packets[2].Type != Delim {
		t.Error("packet 2 should be Delim")
	}
	if packets[6].Type != Flush {
		t.Error("packet 6 should be Flush")
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	input := []byte("000ahello\n" + "0000" + "0001" + "000aworld\n" + "0002")
	packets := Parse(input)
	output := Encode(packets)
	if !bytes.Equal(input, output) {
		t.Fatalf("round-trip failed:\n  input:  %q\n  output: %q", input, output)
	}
}

func TestEncodeEmptyPayload(t *testing.T) {
	packets := []Packet{{Type: Flush}, {Type: Delim}}
	output := Encode(packets)
	if string(output) != "00000001" {
		t.Fatalf("expected %q, got %q", "00000001", string(output))
	}
}
