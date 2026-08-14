package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/dependabot/proxy/internal/gitproto"
	"github.com/dependabot/proxy/internal/proxyctx"
)

// DB contains the metadata of the disk cache
type DB struct {
	sync.RWMutex
	cacheDB  map[Key]*Entry
	cacheDir string

	calls      int
	cached     int
	callCursor int
}

// Key is the key type used in the DB map
type Key struct {
	Method     string `yaml:"method"`
	URL        string `yaml:"URL"`
	HeaderHash string `yaml:"headerHash,omitempty"`
	BodyHash   string `yaml:"bodyHash,omitempty"`
}

// headers to ignore when calculating the header hash
var ignoreHeaders = map[string]struct{}{
	// Seems to slip through when not using auth
	"Proxy-Authorization": {},
	// Theoretically shouldn't matter to the response
	"Connection":      {},
	"Accept-Encoding": {},
	"Keep-Alive":      {},
	// Hopefully should not change the response
	"User-Agent": {},
	// NPM specific
	"Npm-Command": {},
	// NuGet Session ID changes each run
	"X-Nuget-Session-Id": {},
	// Pub: session ID and command are the main issue
	"X-Pub-Command":     {},
	"X-Pub-Environment": {},
	"X-Pub-Os":          {},
	"X-Pub-Reason":      {},
	"X-Pub-Session-Id":  {},
}

// generates the key used in the DB, includes a hash of the body
func key(r *http.Request) Key {
	data, _ := io.ReadAll(r.Body)
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(data))
	k := Key{
		Method: r.Method,
		URL:    r.URL.String(),
	}
	// sort the headers to have a consistent hash
	var headers []string
	for headerKey := range r.Header {
		if _, ok := ignoreHeaders[headerKey]; ok {
			continue
		}
		headers = append(headers, headerKey)
	}
	// Go randomizes map iteration order, so sort the header keys to get a consistent hash
	sort.Strings(headers)
	sortedHeaders := make([]string, 0, len(headers))
	for _, headerKey := range headers {
		// sort the values to get a consistent hash, in case a bump in a package-manager changes the order
		headerValues := append([]string{}, r.Header[headerKey]...)
		sort.Strings(headerValues)
		sortedHeaders = append(sortedHeaders, headerKey)
		sortedHeaders = append(sortedHeaders, headerValues...)
	}
	if len(sortedHeaders) > 0 {
		headerHash := sha256.New()
		for _, v := range sortedHeaders {
			headerHash.Write([]byte(v))
		}
		k.HeaderHash = hex.EncodeToString(headerHash.Sum(nil))
	}
	if len(data) > 0 {
		hashData := data
		if gitproto.IsUploadPackRequest(r) {
			hashData = gitproto.NormalizeUploadPackBody(data)
		}
		hash := sha256.New()
		hash.Write(hashData)
		k.BodyHash = hex.EncodeToString(hash.Sum(nil))
	}
	return k
}

// Entry is an entry of the DB
type Entry struct {
	Status          int         `yaml:"status"`
	FilePath        string      `yaml:"filePath"`
	ResponseHeaders http.Header `yaml:"responseHeaders,omitempty"`

	// only set with PROXY_DEBUG_HEADERS=true
	RequestHeaders http.Header `yaml:"requestHeaders,omitempty"`
}

// Out is used to serialize the DB
type Out struct {
	Key
	*Entry
}

// New creates a new cache
func New(enabled bool, cacheDir string) (*DB, error) {
	if !enabled {
		return nil, nil
	}
	if err := os.Mkdir(cacheDir, 0750); err != nil && !os.IsExist(err) {
		cacheDir = filepath.Join(os.TempDir(), "cache")
	}
	db := &DB{
		cacheDB:  map[Key]*Entry{},
		cacheDir: cacheDir,
	}

	// attempt to load pre-existing DB
	f, err := os.Open(filepath.Clean(filepath.Join(cacheDir, "db.yaml")))
	if err != nil {
		return db, nil
	}
	var in []Out
	if err := yaml.NewDecoder(f).Decode(&in); err != nil {
		logrus.Errorln("db.yaml is unreadable:", err.Error())
		return db, nil
	}
	for i := range in {
		if in[i].Entry != nil && !cacheableStatus(in[i].Entry.Status) {
			// Skip conditional / no-content entries (1xx/204/205/304) persisted
			// by an older proxy. cacheableStatus only gates new writes, so
			// without this filter such entries would still be loaded here and
			// replayed by OnRequest after upgrade, reintroducing the stale-304
			// problem this change is meant to fix.
			continue
		}
		db.cacheDB[in[i].Key] = in[i].Entry
	}
	// prevent successive runs from overwriting previous cache entries
	db.callCursor = len(db.cacheDB)
	return db, nil
}

const (
	wasCached = "cached-response"
	keyValue  = "key"
)

// bodyless reports whether an HTTP response must not carry a message body, per
// RFC 7230 3.3.3: any response to a HEAD request, all 1xx (informational)
// responses, 204 No Content, 205 Reset Content, and 304 Not Modified. The
// client will not read a body for these regardless of framing headers, so if we
// attach a body (or a bogus chunked terminator) the extra bytes are left in the
// connection and desync the next request on the now keep-alive MITM tunnel.
//
// 101 Switching Protocols is deliberately excluded: its "body" is the upgraded
// connection stream (e.g. WebSocket), so it must be passed through untouched.
func bodyless(status int, method string) bool {
	if status == http.StatusSwitchingProtocols {
		return false
	}
	if method == http.MethodHead {
		return true
	}
	switch {
	case status >= 100 && status < 200:
		return true
	case status == http.StatusNoContent,
		status == http.StatusResetContent,
		status == http.StatusNotModified:
		return true
	default:
		return false
	}
}

// cacheableStatus reports whether a response with the given status code is worth
// persisting in the cache. Informational (1xx), no-content (204/205) and
// conditional (304 Not Modified) responses carry no reusable body, so caching
// them saves nothing. Worse, caching a 304 is actively harmful for a dependency
// updater: replaying a stale "Not Modified" hides upstream package updates that
// the client would otherwise fetch, and a client whose local copy no longer
// matches (e.g. pnpm) fails with ERR_PNPM_CACHE_MISSING_AFTER_304. These
// responses are always passed straight through instead.
func cacheableStatus(status int) bool {
	switch {
	case status >= 100 && status < 200:
		return false
	case status == http.StatusNoContent,
		status == http.StatusResetContent,
		status == http.StatusNotModified:
		return false
	default:
		return true
	}
}

// OnRequest checks to see if the response is cached, if so responds with the cached data.
func (d *DB) OnRequest(r *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if d == nil {
		// caching disabled
		return r, nil
	}

	if r.URL.Hostname() == "host.docker.internal" {
		// don't cache test scenario calls
		return r, nil
	}

	if r.URL.Hostname() == "dc.services.visualstudio.com" {
		// don't cache telemetry calls, it messes with the success ratio since none will ever cache
		return r, nil
	}

	d.Lock()
	defer d.Unlock()
	d.calls++

	key := key(r)
	proxyctx.SetValue(proxyCtx, keyValue, key)
	if entry, ok := d.cacheDB[key]; ok {
		resp := &http.Response{}
		resp.Request = r
		resp.Header = entry.ResponseHeaders
		resp.StatusCode = entry.Status

		if bodyless(entry.Status, r.Method) {
			// Serve bodyless responses (1xx/204/205/304/HEAD) with no body and
			// no transfer-encoding so goproxy frames them correctly. Attaching a
			// body here would make goproxy stamp a chunked terminator the
			// client never reads, desyncing the keep-alive MITM tunnel.
			resp.Body = http.NoBody
			resp.ContentLength = 0
			// A HEAD response legitimately advertises the Content-Length the
			// equivalent GET would return. Restore it from the cached headers so
			// a hit reports the same length as the original miss. This is safe
			// only for HEAD: Go skips the ContentLength/body mismatch check for
			// responses to HEAD, whereas a non-HEAD status (e.g. GET 304) with a
			// non-zero ContentLength and an empty body would fail resp.Write.
			if r.Method == http.MethodHead {
				if n, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
					resp.ContentLength = n
				}
			}
			proxyctx.SetValue(proxyCtx, wasCached, true)
			d.cached++
			return r, resp
		}

		f, err := os.Open(entry.FilePath)
		if err != nil {
			// The cache entry exists but its file is gone/unreadable. Fall
			// through to the upstream request without marking it as cached so
			// logs and cache statistics stay accurate.
			logrus.Errorln("failed to open cache file:", err)
			return r, nil
		}
		resp.TransferEncoding = r.TransferEncoding
		resp.Body = f
		// Set ContentLength from the cache file so goproxy can length-delimit
		// the response instead of guessing, avoiding framing ambiguity.
		if fi, statErr := f.Stat(); statErr == nil {
			resp.ContentLength = fi.Size()
		}
		proxyctx.SetValue(proxyCtx, wasCached, true)
		d.cached++
		return r, resp
	}
	return r, nil
}

// OnResponse caches the data in the DB and writes the data to disk.
func (d *DB) OnResponse(resp *http.Response, proxyCtx *goproxy.ProxyCtx) *http.Response {
	if d == nil {
		// caching disabled
		return resp
	}
	if resp == nil {
		// no response to cache
		logrus.Warnln("Received nil response")
		return resp
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// 101: the body is the upgraded connection stream (e.g. WebSocket).
		// Never cache or reframe it.
		return resp
	}
	k, ok := proxyctx.GetValue(proxyCtx, keyValue)
	if !ok {
		// can't calculate key as response body is empty
		// this happens when the OnRequest decides not to cache
		return resp
	}
	key := k.(Key)

	d.Lock()
	defer d.Unlock()
	if _, ok := d.cacheDB[key]; ok {
		// the response is already cached
		return resp
	}

	if bodyless(resp.StatusCode, resp.Request.Method) {
		// Bodyless responses (1xx/204/205/304/HEAD) carry no body. An earlier
		// response handler may have replaced resp.Body with a wrapper (e.g.
		// PythonIndexHandler swaps in a replay reader even for http.NoBody), so
		// we cannot assume it is still http.NoBody here. Close any wrapper and
		// restore http.NoBody so goproxy sees an unmodified empty body and frames
		// the response without a chunked terminator. Leaving a non-NoBody body in
		// place would make goproxy stamp a "0\r\n\r\n" the client never reads,
		// desyncing the keep-alive MITM tunnel. This normalization runs whether
		// or not we go on to cache the response.
		if resp.Body != nil && resp.Body != http.NoBody {
			_ = resp.Body.Close()
			resp.Body = http.NoBody
		}

		if !cacheableStatus(resp.StatusCode) {
			// Never cache conditional / no-content responses (1xx/204/205/304).
			// A cached 304 would replay a stale "Not Modified" and hide upstream
			// package updates from the updater; there is no body to reuse anyway.
			// Pass it straight through, correctly framed.
			return resp
		}

		// A HEAD response for an otherwise cacheable status (e.g. 200) has no
		// body but carries useful headers (notably Content-Length). Cache it
		// headers-only so a later HEAD hit reproduces the same metadata.
		d.cacheDB[key] = &Entry{
			Status:          resp.StatusCode,
			ResponseHeaders: resp.Header,
		}
		return resp
	}

	fileName := fmt.Sprintf("%06d-%v", d.nextNumber(), sanitize(resp.Request.Host))
	f, err := os.Create(filepath.Clean(filepath.Join(d.cacheDir, fileName)))
	if err != nil {
		logrus.Warnln("Failed to write to cache:", err.Error())
		return resp
	}

	resp.Body = TeeReadCloser(resp.Body, f, func() {
		d.Lock()
		defer d.Unlock()

		entry := &Entry{
			FilePath:        f.Name(),
			Status:          resp.StatusCode,
			ResponseHeaders: resp.Header,
		}

		if os.Getenv("PROXY_DEBUG_HEADERS") == "true" {
			for k := range resp.Request.Header {
				if _, ok := ignoreHeaders[k]; ok {
					resp.Request.Header.Del(k)
				}
			}
			entry.RequestHeaders = resp.Request.Header
		}

		d.cacheDB[key] = entry
	})
	return resp
}

var sanitizeRegex = regexp.MustCompile(`\W`)

func sanitize(host string) string {
	return sanitizeRegex.ReplaceAllString(host, "-")
}

func (d *DB) nextNumber() int {
	d.callCursor++
	return d.callCursor
}

// Statistics logs caching stats.
func (d *DB) Statistics() {
	percentage := float64(d.cached) / (float64(d.calls) + math.SmallestNonzeroFloat64) * 100.
	logrus.Infof("%v/%v calls cached (%v%%)", d.cached, d.calls, int(percentage))
}

// WriteToDisk outputs the db in the cache directory for scenario use.
func (d *DB) WriteToDisk() error {
	d.Lock()
	defer d.Unlock()

	f, err := os.Create(filepath.Clean(filepath.Join(d.cacheDir, "db.yaml")))
	if err != nil {
		logrus.Errorln("Failed to create db file:", err.Error())
		return err
	}
	var out []Out
	for key, entry := range d.cacheDB {
		k := key
		e := entry
		out = append(out, Out{k, e})
	}
	// since Go maps randomize, sorting helps see real changes in the DB on disk
	sort.Slice(out, func(i, j int) bool {
		return out[i].FilePath < out[j].FilePath
	})
	if err = yaml.NewEncoder(f).Encode(out); err != nil {
		logrus.Errorln("Failed to marshal DB:", err.Error())
		return err
	}
	return nil
}

// TeeReadCloser is an io.TeeReader that also closes, and calls the callback after all streams are closed.
// The callback is only called if there were no errors closing the reader. This is so that if
// the connection is severed or the file is corrupted we don't cache. If there's a problem with the writer,
// it finishes reading still and skips the callback. That way if the disk is full we don't cache but
// the read is successful.
func TeeReadCloser(r io.ReadCloser, w io.WriteCloser, callback func()) io.ReadCloser {
	return &teeReader{
		r:        r,
		w:        w,
		callback: callback,
	}
}

type teeReader struct {
	r        io.ReadCloser
	w        io.WriteCloser
	callback func()
	writeErr error
}

func (t *teeReader) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 && t.writeErr == nil {
		m, err := t.w.Write(p[:n])
		if err != nil {
			t.writeErr = err
			return n, nil
		}
		n = m
	}
	return
}

func (t *teeReader) Close() error {
	err := t.r.Close()
	_ = t.w.Close()
	if err != nil {
		return err
	}
	if t.writeErr != nil {
		return nil
	}
	t.callback()
	return nil
}

// WasResponseCached returns true if the response was cached.
func WasResponseCached(proxyCtx *goproxy.ProxyCtx) bool {
	cached, ok := proxyctx.GetBool(proxyCtx, wasCached)
	if !ok {
		return false
	}
	return cached
}
