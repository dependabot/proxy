// Package pktline implements parsing and encoding of the git pkt-line format.
//
// The pkt-line format is used by the git smart HTTP protocol (git-upload-pack,
// git-receive-pack) to frame variable-length data. Each line is prefixed with a
// 4-hex-digit length that includes itself, or is a special packet:
//
//   - "0000" flush packet (stream boundary)
//   - "0001" delimiter packet (section separator, protocol v2)
//   - "0002" response-end packet
//   - "0003" reserved
//   - "0004"+ data packet with payload of (length - 4) bytes
//
// See https://git-scm.com/docs/protocol-common#_pkt_line_format
package pktline

import (
	"fmt"
	"strconv"
)

// PacketType identifies the kind of pkt-line packet.
type PacketType int

const (
	// Data is a normal data packet with a payload.
	Data PacketType = iota
	// Flush is the "0000" packet indicating a stream boundary.
	Flush
	// Delim is the "0001" packet separating sections in protocol v2.
	Delim
	// ResponseEnd is the "0002" packet indicating the end of a response.
	ResponseEnd
)

// Packet represents a single pkt-line packet.
type Packet struct {
	Type    PacketType
	Payload []byte // nil for Flush, Delim, ResponseEnd
}

// Parse parses a pkt-line byte stream into a slice of packets.
// If the stream contains malformed data (bad length prefix, truncated packet),
// the remainder is returned as a single Data packet so callers can degrade
// gracefully rather than losing data.
func Parse(data []byte) []Packet {
	var packets []Packet
	for len(data) > 0 {
		if len(data) < 4 {
			packets = append(packets, Packet{Type: Data, Payload: data})
			break
		}

		length, err := strconv.ParseUint(string(data[:4]), 16, 16)
		if err != nil {
			packets = append(packets, Packet{Type: Data, Payload: data})
			break
		}

		switch {
		case length == 0:
			packets = append(packets, Packet{Type: Flush})
			data = data[4:]
		case length == 1:
			packets = append(packets, Packet{Type: Delim})
			data = data[4:]
		case length == 2:
			packets = append(packets, Packet{Type: ResponseEnd})
			data = data[4:]
		case length == 3:
			// Reserved; treat as opaque data
			packets = append(packets, Packet{Type: Data, Payload: data[:4]})
			data = data[4:]
		default:
			if int(length) > len(data) {
				// Truncated packet; include remainder as-is
				packets = append(packets, Packet{Type: Data, Payload: data})
				data = nil
			} else {
				packets = append(packets, Packet{Type: Data, Payload: data[4:length]})
				data = data[length:]
			}
		}
	}
	return packets
}

// Encode serializes a slice of packets back into the pkt-line wire format.
func Encode(packets []Packet) []byte {
	var buf []byte
	for _, p := range packets {
		switch p.Type {
		case Flush:
			buf = append(buf, "0000"...)
		case Delim:
			buf = append(buf, "0001"...)
		case ResponseEnd:
			buf = append(buf, "0002"...)
		case Data:
			buf = append(buf, fmt.Sprintf("%04x", 4+len(p.Payload))...)
			buf = append(buf, p.Payload...)
		}
	}
	return buf
}
