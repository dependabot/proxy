package gitproto

// pkt-line is git's smart-HTTP framing format. Each line begins with a
// 4-hex-digit length (including itself), or is one of three special packets:
// "0000" flush, "0001" delim (v2), "0002" response-end. Any length >= 4 is a
// data packet whose payload is (length - 4) bytes.
// See https://git-scm.com/docs/protocol-common#_pkt_line_format

const hexDigits = "0123456789abcdef"

type pktType int

const (
	pktData pktType = iota
	pktFlush
	pktDelim
	pktResponseEnd
)

// payload is set only when typ == pktData and excludes the length prefix.
type packet struct {
	typ     pktType
	payload []byte
}

// parseHex4 decodes a 4-byte ASCII hex prefix without allocating a string.
func parseHex4(b []byte) (n int, ok bool) {
	for i := 0; i < 4; i++ {
		c := b[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'f':
			v = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = int(c-'A') + 10
		default:
			return 0, false
		}
		n = n<<4 | v
	}
	return n, true
}

// parsePktLine returns ok=false on malformed or truncated input so callers
// can fall back to opaque hashing of the original bytes.
func parsePktLine(data []byte) (packets []packet, ok bool) {
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, false
		}
		n, ok := parseHex4(data[:4])
		if !ok {
			return nil, false
		}
		switch n {
		case 0:
			packets = append(packets, packet{typ: pktFlush})
			data = data[4:]
		case 1:
			packets = append(packets, packet{typ: pktDelim})
			data = data[4:]
		case 2:
			packets = append(packets, packet{typ: pktResponseEnd})
			data = data[4:]
		case 3:
			// Reserved; not used by real git. Treat as malformed.
			return nil, false
		default:
			if n > len(data) {
				return nil, false
			}
			packets = append(packets, packet{typ: pktData, payload: data[4:n]})
			data = data[n:]
		}
	}
	return packets, true
}

// encodePktLine recomputes each data packet's length prefix, which is what
// makes normalization stable across payloads of differing length.
func encodePktLine(packets []packet) []byte {
	buf := make([]byte, 0, encodedSize(packets))
	for _, p := range packets {
		switch p.typ {
		case pktFlush:
			buf = append(buf, "0000"...)
		case pktDelim:
			buf = append(buf, "0001"...)
		case pktResponseEnd:
			buf = append(buf, "0002"...)
		case pktData:
			n := 4 + len(p.payload)
			buf = append(buf,
				hexDigits[(n>>12)&0xf],
				hexDigits[(n>>8)&0xf],
				hexDigits[(n>>4)&0xf],
				hexDigits[n&0xf],
			)
			buf = append(buf, p.payload...)
		}
	}
	return buf
}

func encodedSize(packets []packet) int {
	size := 0
	for _, p := range packets {
		size += 4
		if p.typ == pktData {
			size += len(p.payload)
		}
	}
	return size
}
