// Package gitproto provides helpers for stabilizing git smart-HTTP cache keys.
//
// Only IsUploadPackRequest and NormalizeUploadPackBody are exported; the
// pkt-line framing parser is an implementation detail.
package gitproto

import (
	"bytes"
	"mime"
	"net/http"
	"regexp"
	"strings"
)

// uploadPackContentType is the media type real git clients send on a fetch.
// See https://git-scm.com/docs/http-protocol.
const uploadPackContentType = "application/x-git-upload-pack-request"

// inlineVolatileTokenRegex matches " agent=…" / " session-id=…" tokens
// trailing a v1 capability list. The leading space anchors the match so a
// payload that merely starts with the same text is not affected.
var inlineVolatileTokenRegex = regexp.MustCompile(` (?:agent|session-id)=[^ \r\n]*`)

// volatileStandalonePrefixes lists payload prefixes whose entire pkt-line is
// dropped: per-process v2 capability lines that don't influence the pack.
//
// "have" lines are intentionally NOT here — they drive object negotiation and
// the upstream response depends on them.
var volatileStandalonePrefixes = [][]byte{[]byte("agent="), []byte("session-id=")}

// hasVolatilePrefix reports whether payload begins with any prefix in
// volatileStandalonePrefixes.
func hasVolatilePrefix(payload []byte) bool {
	for _, prefix := range volatileStandalonePrefixes {
		if bytes.HasPrefix(payload, prefix) {
			return true
		}
	}
	return false
}

// IsUploadPackRequest reports whether r is a smart-HTTP git-upload-pack POST.
// All three of method, path suffix, and Content-Type must match so that an
// unrelated POST sharing the URL suffix isn't routed through normalization.
func IsUploadPackRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if !strings.HasSuffix(r.URL.Path, "/git-upload-pack") {
		return false
	}
	// mime.ParseMediaType handles RFC 7231 case-insensitivity and parameter
	// whitespace; we only care about the canonical media type.
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == uploadPackContentType
}

// NormalizeUploadPackBody returns a stable cache-key input derived from a
// git-upload-pack POST body. The output is hash input only — never sent on
// the wire.
//
// Stripped (per-process noise that doesn't shape the pack):
//   - standalone "agent=" / "session-id=" pkt-lines (v2 capabilities)
//   - inline " agent=" / " session-id=" tokens on v1 want lines
//
// Preserved (everything that can change the upstream response): wants, haves,
// capabilities, command=, deepen/shallow, filter, ref-prefix, object-format,
// and all framing packets. Re-encoding recomputes pkt-line length prefixes,
// so requests differing only in a stripped value's length still hash equal.
//
// Malformed input is returned unchanged so callers fall back to opaque
// hashing (cache miss is acceptable; collision is not).
func NormalizeUploadPackBody(data []byte) []byte {
	packets, ok := parsePktLine(data)
	if !ok {
		return data
	}
	filtered := packets[:0]
	for _, p := range packets {
		if p.typ != pktData {
			filtered = append(filtered, p)
			continue
		}
		if hasVolatilePrefix(p.payload) {
			continue
		}
		// Match-then-Replace skips the alloc on the common no-match path.
		if inlineVolatileTokenRegex.Match(p.payload) {
			cleaned := inlineVolatileTokenRegex.ReplaceAll(p.payload, nil)
			filtered = append(filtered, packet{typ: pktData, payload: cleaned})
			continue
		}
		filtered = append(filtered, p)
	}
	return encodePktLine(filtered)
}
