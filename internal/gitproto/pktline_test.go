package gitproto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePktLine_Empty(t *testing.T) {
	pkts, ok := parsePktLine(nil)
	assert.True(t, ok)
	assert.Empty(t, pkts)
}

func TestParsePktLine_SpecialPackets(t *testing.T) {
	cases := map[string]pktType{
		"0000": pktFlush,
		"0001": pktDelim,
		"0002": pktResponseEnd,
	}
	for input, want := range cases {
		pkts, ok := parsePktLine([]byte(input))
		assert.True(t, ok)
		if assert.Len(t, pkts, 1) {
			assert.Equal(t, want, pkts[0].typ)
		}
	}
}

func TestParsePktLine_DataPacket(t *testing.T) {
	// "000ahello\n" = length 0x000a (10), payload "hello\n"
	pkts, ok := parsePktLine([]byte("000ahello\n"))
	assert.True(t, ok)
	if assert.Len(t, pkts, 1) {
		assert.Equal(t, pktData, pkts[0].typ)
		assert.Equal(t, "hello\n", string(pkts[0].payload))
	}
}

func TestParsePktLine_MalformedAndTruncated(t *testing.T) {
	// Bad hex prefix.
	pkts, ok := parsePktLine([]byte("gggghi"))
	assert.False(t, ok)
	assert.Nil(t, pkts)
	// Length claims 0x0020 but only 9 bytes available.
	pkts, ok = parsePktLine([]byte("0020short"))
	assert.False(t, ok)
	assert.Nil(t, pkts)
	// Length 3 is reserved; we treat as malformed.
	pkts, ok = parsePktLine([]byte("00030000"))
	assert.False(t, ok)
	assert.Nil(t, pkts)
	// Less than 4 bytes.
	pkts, ok = parsePktLine([]byte("ab"))
	assert.False(t, ok)
	assert.Nil(t, pkts)
}

func TestParsePktLine_RealV1Body(t *testing.T) {
	// Realistic v1 upload-pack body from github.com/octocat/Hello-World
	input := "00a4want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d multi_ack_detailed no-done side-band-64k thin-pack no-progress ofs-delta deepen-since deepen-not agent=git/2.43.0\n" +
		"0032want b1b3f9723831141a31a1a7252a213e216ea76e56\n" +
		"0000" +
		"0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n" +
		"0009done\n"
	pkts, ok := parsePktLine([]byte(input))
	require.True(t, ok)
	wantTypes := []pktType{pktData, pktData, pktFlush, pktData, pktData}
	require.Len(t, pkts, len(wantTypes))
	for i, want := range wantTypes {
		assert.Equal(t, want, pkts[i].typ)
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
	require.True(t, ok)
	require.Len(t, pkts, 7)
	assert.Equal(t, pktDelim, pkts[2].typ)
	assert.Equal(t, pktFlush, pkts[6].typ)
}

func TestEncodePktLine_RoundTrip(t *testing.T) {
	input := []byte("000ahello\n" + "0000" + "0001" + "000aworld\n" + "0002")
	pkts, ok := parsePktLine(input)
	require.True(t, ok)
	assert.Equal(t, input, encodePktLine(pkts))
}
