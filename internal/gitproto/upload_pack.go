// Package gitproto implements a small set of operations on the git smart-HTTP
// wire protocol, in support of the proxy's disk cache.
//
// The exported surface is intentionally narrow: callers should only need
// IsUploadPackRequest and NormalizeUploadPackBody. The pkt-line framing format
// is an internal implementation detail.
package gitproto

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"
)

// gitInlineVolatileRegex matches volatile inline capability tokens — currently
// " agent=<version>" and " session-id=<uuid>" — that appear as trailing
// capabilities on a v1 upload-pack want line. Real git always emits these
// after a leading space, so the leading-space anchor distinguishes them from
// a payload that merely starts with the same prefix.
var gitInlineVolatileRegex = regexp.MustCompile(` (?:agent|session-id)=[^ \r\n]*`)

// volatileStandalonePrefixes lists payload prefixes whose entire pkt-line is
// dropped from the normalized body. These are protocol-v2 capability or
// negotiation lines that vary between semantically identical requests:
//
//   - "have "       local object negotiation state, varies per client
//   - "agent="      v2 client version capability
//   - "session-id=" v2 trace2 session identifier (Git 2.36+), unique per invocation
var volatileStandalonePrefixes = [][]byte{[]byte("have "), []byte("agent="), []byte("session-id=")}

// IsUploadPackRequest reports whether r is a POST to a git-upload-pack
// endpoint, i.e. a smart-HTTP fetch negotiation.
func IsUploadPackRequest(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-upload-pack")
}

// NormalizeUploadPackBody returns a normalized form of a git-upload-pack POST
// body, suitable for use as a stable cache-key input.
//
// The output is opaque hash input — not intended to be sent on the wire.
//
// Normalization removes only fields that vary between semantically identical
// requests:
//
//   - "have" pkt-lines (local object negotiation state, varies per client)
//   - Standalone "agent=" pkt-lines (protocol v2 client version)
//   - Standalone "session-id=" pkt-lines (protocol v2 trace2 session id, Git 2.36+)
//   - Inline " agent=" and " session-id=" tokens within v1 capability lines
//
// All response-shaping fields (want, capabilities, command=, deepen, filter,
// shallow, ref-prefix, object-format, ...) are preserved, and special framing
// packets (flush, delim, response-end) are preserved verbatim. Each retained
// Data packet is re-emitted with a recomputed length prefix, so two requests
// that differ only in the length of a volatile field still hash identically.
//
// If the body is not valid pkt-line data, it is returned unchanged so callers
// fall back to full-body hashing (cache miss, never collision).
//
// Safety contract: this is safe to use as a cache key in environments where
// "have" sets are stable across runs (e.g. ephemeral containers with no
// pre-existing git objects, as used by Dependabot updaters). Under that
// assumption an upstream response generated for one normalized request body
// is valid for any request that normalizes to the same bytes.
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
		payload := p.payload
		dropped := false
		for _, prefix := range volatileStandalonePrefixes {
			if bytes.HasPrefix(payload, prefix) {
				dropped = true
				break
			}
		}
		if dropped {
			continue
		}
		if gitInlineVolatileRegex.Match(payload) {
			cleaned := gitInlineVolatileRegex.ReplaceAll(payload, nil)
			filtered = append(filtered, packet{typ: pktData, payload: cleaned})
			continue
		}
		filtered = append(filtered, p)
	}
	return encodePktLine(filtered)
}
