package gitproto

// pkt-line is the framing format used by the git smart-HTTP protocol
// (git-upload-pack, git-receive-pack). Each line is prefixed with a 4-hex-digit
// length that includes itself, or is a special packet:
//
//   - "0000" flush (stream boundary)
//   - "0001" delim (section separator, protocol v2)
//   - "0002" response-end
//   - "0004"+ data packet with payload of (length - 4) bytes
//
// See https://git-scm.com/docs/protocol-common#_pkt_line_format

const hexDigits = "0123456789abcdef"

type pktType int

const (
	pktData pktType = iota
	pktFlush
	pktDelim
	pktResponseEnd
)

type packet struct {
	typ     pktType
	payload []byte // nil for non-data packets
}

// parseHex4 decodes a 4-byte ASCII hex prefix into its integer value without
// allocating an intermediate string. Returns ok=false on any non-hex byte.
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

// parsePktLine parses a pkt-line byte stream into packets. The returned ok
// flag is false when the stream contains malformed or truncated data, in
// which case the packets slice is nil and callers should fall back to
// treating the original input opaquely (e.g., hashing it whole).
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
			// Reserved by the spec; not used by real git. Treat as
			// malformed so callers fall back to full-input behaviour.
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

// encodePktLine serializes packets back into the pkt-line wire format.
// Re-encoding recomputes each data packet's length prefix, which is what
// makes upstream normalization correct across requests whose payloads
// differ only in length (e.g. different agent string lengths).
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
