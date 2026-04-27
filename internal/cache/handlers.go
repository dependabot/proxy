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
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/dependabot/proxy/internal/pktline"

	"github.com/dependabot/proxy/internal/ctxdata"
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

// gitInlineAgentRegex matches the volatile inline "agent=" capability token
// in v1 want lines (e.g., " agent=git/2.43.0-Linux"). Real git always emits
// agent= as a trailing capability after a leading space.
var gitInlineAgentRegex = regexp.MustCompile(` agent=[^ \r\n]*`)

// isGitUploadPack returns true if the request is a POST to a git-upload-pack endpoint.
func isGitUploadPack(r *http.Request) bool {
	return r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/git-upload-pack")
}

// normalizeGitBody parses the pkt-line stream from a git-upload-pack POST body
// and rebuilds it with volatile fields removed, producing a stable cache key.
//
// Specifically:
//   - "have" lines are dropped (local negotiation state that varies between clients)
//   - Standalone "agent=" pkt-lines (v2) are dropped
//   - Inline " agent=" tokens in v1 capability lines are stripped
//   - All other lines (want, deepen, filter, command, shallow, etc.) are preserved
//     with recomputed pkt-line length prefixes
//   - Special packets (flush 0000, delim 0001, response-end 0002) are preserved
//
// If the body is not valid pkt-line data, it is included as-is so the hash falls
// back to full-body behavior (cache miss, not corruption).
//
// Safety assumption: Dependabot updaters run in clean ephemeral containers with
// no pre-existing git objects, so "have" negotiation state is effectively
// identical across runs for any ecosystem that uses git-upload-pack (nix, bundler
// git sources, Go modules, git submodules, etc.). Stripping "have" lines is safe
// because the server response does not depend on local object state when haves
// are empty or near-empty.
func normalizeGitBody(data []byte) []byte {
	packets := pktline.Parse(data)
	var filtered []pktline.Packet
	for _, p := range packets {
		if p.Type != pktline.Data {
			filtered = append(filtered, p)
			continue
		}
		payload := string(p.Payload)

		// Drop "have" lines
		if strings.HasPrefix(payload, "have ") {
			continue
		}

		// Drop standalone "agent=" pkt-lines (v2)
		if strings.HasPrefix(payload, "agent=") {
			continue
		}

		// Strip inline " agent=" tokens from v1 capability lines
		cleaned := gitInlineAgentRegex.ReplaceAllString(payload, "")
		filtered = append(filtered, pktline.Packet{Type: pktline.Data, Payload: []byte(cleaned)})
	}
	return pktline.Encode(filtered)
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
		if isGitUploadPack(r) {
			hashData = normalizeGitBody(data)
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

// OnRequest checks to see if the response is cached, if so responds with the cached data.
func (d *DB) OnRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
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
	ctxdata.SetValue(ctx, keyValue, key)
	if entry, ok := d.cacheDB[key]; ok {
		f, err := os.Open(entry.FilePath)
		if err != nil {
			logrus.Errorln("failed to open cache file:", err)
			return r, nil
		}
		ctxdata.SetValue(ctx, wasCached, true)
		d.cached++
		resp := &http.Response{}
		resp.Request = r
		resp.TransferEncoding = r.TransferEncoding
		resp.Header = entry.ResponseHeaders
		resp.StatusCode = entry.Status
		resp.Body = f
		return r, resp
	}
	return r, nil
}

// OnResponse caches the data in the DB and writes the data to disk.
func (d *DB) OnResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if d == nil {
		// caching disabled
		return resp
	}
	if resp == nil {
		// no response to cache
		logrus.Warnln("Received nil response")
		return resp
	}
	k, ok := ctxdata.GetValue(ctx, keyValue)
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
func WasResponseCached(ctx *goproxy.ProxyCtx) bool {
	cached, ok := ctxdata.GetBool(ctx, wasCached)
	if !ok {
		return false
	}
	return cached
}
