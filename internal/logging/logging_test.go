package logging

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/testhelpers"
)

func TestRequestLogf(t *testing.T) {
	proxyCtx := &goproxy.ProxyCtx{Session: 128}

	testCases := map[string]struct {
		format   string
		argv     []any
		expected string
	}{
		"leading/trailing whitespace": {
			format:   "  the quick brown %s jumped over the lazy %s  \n",
			argv:     []any{"fox", "dog"},
			expected: "[128]   the quick brown fox jumped over the lazy dog\n",
		},
		"newlines": {
			format:   "the quick brown %s jumped over the lazy %s\n",
			argv:     []any{"fox\n\n", "dog\n"},
			expected: "[128] the quick brown fox  jumped over the lazy dog\n",
		},
		"carriage returns": {
			format:   "the quick brown %s jumped over the lazy %s\r",
			argv:     []any{"fox\r\r", "dog\r"},
			expected: "[128] the quick brown fox  jumped over the lazy dog\n",
		},
		"newlines and carriage returns": {
			format:   "the quick brown %s jumped over the lazy %s\n\r",
			argv:     []any{"fox\n\r", "dog\n\r"},
			expected: "[128] the quick brown fox  jumped over the lazy dog\n",
		},
		"truncates to 1024 bytes": {
			// Formatted string len: 1152 bytes
			format: "%s\n%s\n%s\n",
			argv: []any{
				strings.Repeat("x", 127),
				strings.Repeat("y", 511),
				strings.Repeat("z", 511),
			},
			// Formatted string len: 1024 bytes
			expected: fmt.Sprintf(
				"[128] %s %s %s\n",
				strings.Repeat("x", 127),
				strings.Repeat("y", 511),
				strings.Repeat("z", 377),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			testhelpers.CaptureStandardLog(t, &buf)

			RequestLogf(proxyCtx, tc.format, tc.argv...)

			actual := buf.String()
			assert.True(t, strings.HasSuffix(actual, tc.expected))
		})
	}
}

func TestRequestMultilineLogf(t *testing.T) {
	proxyCtx := &goproxy.ProxyCtx{Session: 128}

	testCases := map[string]struct {
		format   string
		argv     []any
		expected string
	}{
		"leading/trailing whitespace": {
			format:   "\n\nthe quick brown %s jumped over the lazy %s  \n",
			argv:     []any{"fox\n\n", "dog\n\n"},
			expected: "[128] the quick brown fox\n jumped over the lazy dog\n",
		},
		"newlines": {
			format:   "the quick brown %s jumped over the lazy %s\n",
			argv:     []any{"fox\n\n", "dog\n"},
			expected: "[128] the quick brown fox\n jumped over the lazy dog\n",
		},
		"carriage returns": {
			format:   "the quick brown %s jumped over the lazy %s\r",
			argv:     []any{"fox\r\r", "dog\r"},
			expected: "[128] the quick brown fox\n jumped over the lazy dog\n",
		},
		"newlines and carriage returns": {
			format:   "the quick brown %s jumped over the lazy %s\n\r",
			argv:     []any{"fox\n\r", "dog\n\r"},
			expected: "[128] the quick brown fox\n jumped over the lazy dog\n",
		},
		"truncates to 1024 bytes": {
			// Formatted string len: 1152 bytes
			format: "%s\n%s\n%s\n",
			argv: []any{
				strings.Repeat("x", 127),
				strings.Repeat("y", 511),
				strings.Repeat("z", 511),
			},
			// Formatted string len: 1024 bytes
			expected: fmt.Sprintf(
				"[128] %s\n%s\n%s\n",
				strings.Repeat("x", 127),
				strings.Repeat("y", 511),
				strings.Repeat("z", 377),
			),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			testhelpers.CaptureStandardLog(t, &buf)

			RequestMultilineLogf(proxyCtx, tc.format, tc.argv...)

			actual := buf.String()
			assert.True(t, strings.HasSuffix(actual, tc.expected))
		})
	}
}
