package logging

import (
	"fmt"
	"github.com/dependabot/proxy/internal/cache"
	"log"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/elazarl/goproxy"
)

// RequestLogf builds a log entry from format and v according to the semantics
// of fmt.Sprintf and logs it. All sequences of newlines and/or carriage
// returns in the resulting entry are replaced with a space, any trailing
// spaces are removed, and the entry is logged with a single trailing newline.
// If p is given, the logged line is prefixed with a three-digit representation
// of p.Session.
func RequestLogf(ctx *goproxy.ProxyCtx, format string, v ...any) {
	formatted := fmt.Sprintf(format, v...)
	message := replaceNewLines(formatted, " ")
	requestLog(ctx, message)
}

// RequestMultilineLogf builds a log entry from format and v according to the
// semantics of fmt.Sprintf and logs it. If the resulting entry contains
// newlines and/or carriage returns, they are preserved. The resulting
// entry is truncated to 1024 bytes and it is logged with a single trailing
// newline. If p is given, the first line logged is prefixed with a three-digit
// representation of p.Session.
func RequestMultilineLogf(ctx *goproxy.ProxyCtx, format string, v ...any) {
	formatted := fmt.Sprintf(format, v...)
	message := replaceNewLines(formatted, "\n")
	requestLog(ctx, message)
}

func requestLog(ctx *goproxy.ProxyCtx, message string) {
	format := "%s"
	argv := []any{trimSpace(message)}
	if ctx != nil {
		// Log the request number as a 3-digit number
		reqId := ctx.Session % 1000
		format = "[%03d] " + format
		argv = append([]any{reqId}, argv...)

		if cache.WasResponseCached(ctx) {
			format = format + " (cached)"
		}
	}
	formatted := fmt.Sprintf(format, argv...)
	truncated := truncate(formatted, 1024)
	log.Println(truncated)
}

var lineSep = regexp.MustCompile("[\n\r]+")

func replaceNewLines(s string, replacement string) string {
	return lineSep.ReplaceAllString(s, replacement)
}

// trimSpace trims all whitespace at the end of s and all whitespace except for
// spaces at the start of s (allowing for message indentation in logs).
func trimSpace(s string) string {
	s = strings.TrimLeftFunc(s, func(r rune) bool {
		if r == ' ' {
			return false
		}
		return unicode.IsSpace(r)
	})
	s = strings.TrimRightFunc(s, unicode.IsSpace)
	return s
}

func truncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	index := 0
	prevRuneWidth := 0
	for {
		_, prevRuneWidth = utf8.DecodeRuneInString(s[index:])
		if index+prevRuneWidth >= maxBytes {
			break
		}
		index += prevRuneWidth
	}
	return s[:index]
}
