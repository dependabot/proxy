package gitproto

import (
	"fmt"
	"strconv"
)

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

type pktType int

const (
	pktData pktType = iota
	pktFlush
	pktDelim
	pktResponseEnd
)

type packet struct {
	typ     pktType
	payload []byte // nil for non-Data packets
}

// parsePktLine parses a pkt-line byte stream into packets. The returned ok flag
// is false when the stream contains malformed or truncated data; the unparsed
// remainder is appended as a final Data packet so callers can degrade
// gracefully (e.g., fall back to hashing the raw input).
func parsePktLine(data []byte) (packets []packet, ok bool) {
	for len(data) > 0 {
		if len(data) < 4 {
			packets = append(packets, packet{typ: pktData, payload: data})
			return packets, false
		}
		length64, err := strconv.ParseUint(string(data[:4]), 16, 16)
		if err != nil {
			packets = append(packets, packet{typ: pktData, payload: data})
			return packets, false
		}
		length := int(length64)
		switch {
		case length == 0:
			packets = append(packets, packet{typ: pktFlush})
			data = data[4:]
		case length == 1:
			packets = append(packets, packet{typ: pktDelim})
			data = data[4:]
		case length == 2:
			packets = append(packets, packet{typ: pktResponseEnd})
			data = data[4:]
		case length == 3:
			// Reserved by the spec; not used by real git. Treat as malformed
			// so callers fall back to full-input behaviour.
			packets = append(packets, packet{typ: pktData, payload: data})
			return packets, false
		default:
			if length > len(data) {
				packets = append(packets, packet{typ: pktData, payload: data})
				return packets, false
			}
			packets = append(packets, packet{typ: pktData, payload: data[4:length]})
			data = data[length:]
		}
	}
	return packets, true
}

// encodePktLine serializes packets back into the pkt-line wire format.
// Re-encoding recomputes each Data packet's length prefix, which is what makes
// upstream normalization correct across requests whose data payloads differ
// only in length (e.g. different agent string lengths).
func encodePktLine(packets []packet) []byte {
	var buf []byte
	for _, p := range packets {
		switch p.typ {
		case pktFlush:
			buf = append(buf, "0000"...)
		case pktDelim:
			buf = append(buf, "0001"...)
		case pktResponseEnd:
			buf = append(buf, "0002"...)
		case pktData:
			buf = append(buf, fmt.Sprintf("%04x", 4+len(p.payload))...)
			buf = append(buf, p.payload...)
		}
	}
	return buf
}
