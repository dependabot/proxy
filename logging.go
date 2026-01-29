package main

import (
	"bytes"
	"fmt"
	"github.com/dependabot/proxy/internal/logging"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
)

type requestLogger struct {
}

func NewRequestLogger() *requestLogger {
	return &requestLogger{}
}

func (l *requestLogger) logRequest(req *http.Request, p *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	logging.RequestLogf(p, "%s %s", req.Method, urlWithoutCredentials(req.URL))
	return req, nil
}

func (l *requestLogger) logResponse(rsp *http.Response, p *goproxy.ProxyCtx) *http.Response {
	if rsp == nil {
		logging.RequestLogf(p, "No response from server")
		return rsp
	}

	if rsp.Request == nil {
		logging.RequestLogf(p, "%d (No request on response object)", rsp.StatusCode)
		return rsp
	}

	if rsp.Request.URL == nil {
		logging.RequestLogf(p, "%d (No URL on response.Request object)", rsp.StatusCode)
		return rsp
	}

	logging.RequestLogf(p, "%d %s", rsp.StatusCode, urlWithoutCredentials(rsp.Request.URL))

	if _, logForStatusCode := responseBodyLoggingStatusCodes[rsp.StatusCode]; logForStatusCode {
		logResponseBody(rsp, p, 1024)
	}

	return rsp
}

var responseBodyLoggingStatusCodes = map[int]bool{
	http.StatusBadRequest:        true,
	http.StatusUnauthorized:      true,
	http.StatusForbidden:         true,
	http.StatusProxyAuthRequired: true,
}

type multiCloser struct {
	closers []io.Closer
}

func (mc *multiCloser) Close() (err error) {
	for _, c := range mc.closers {
		if e := c.Close(); e != nil && err == nil {
			err = e
		}
	}
	return
}

type multiReadCloser struct {
	mr io.Reader
	mc io.Closer
}

func (mrc *multiReadCloser) Read(p []byte) (int, error) {
	return mrc.mr.Read(p)
}

func (mrc *multiReadCloser) Close() error {
	return mrc.mc.Close()
}

func sortedHeaderKeys(h http.Header) []string {
	keys := make([]string, len(h))
	i := 0
	for k := range h {
		keys[i] = k
		i += 1
	}
	sort.Strings(keys)
	return keys
}

func newMultiReadCloser(rcs ...io.ReadCloser) io.ReadCloser {
	readers := make([]io.Reader, 0, len(rcs))
	closers := make([]io.Closer, 0, len(rcs))
	for _, r := range rcs {
		readers = append(readers, r)
		closers = append(closers, r)
	}
	return &multiReadCloser{
		mr: io.MultiReader(readers...),
		mc: &multiCloser{closers: closers},
	}
}

func logResponseBody(rsp *http.Response, p *goproxy.ProxyCtx, maxBytes int) {
	if maxBytes > 0 {
		bodyBytes := make([]byte, maxBytes)
		n, err := io.ReadFull(rsp.Body, bodyBytes)
		if n > 0 {
			logging.RequestMultilineLogf(p, "Remote response: %s", string(bodyBytes[:n]))

			if err == io.EOF || err == io.ErrUnexpectedEOF {
				rsp.Body.Close()
				rsp.Body = io.NopCloser(bytes.NewReader(bodyBytes[:n]))
			} else {
				rsp.Body = newMultiReadCloser(io.NopCloser(bytes.NewReader(bodyBytes[:n])), rsp.Body)
			}
		}
	} else {
		bodyBytes, _ := io.ReadAll(rsp.Body)
		rsp.Body.Close()

		logging.RequestMultilineLogf(p, "Remote response: %s", string(bodyBytes))
		rsp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
}

const placeholder = "xxx"

func urlWithoutCredentials(u *url.URL) string {
	cloned := *u

	if u.User != nil {
		cloned.User = userWithoutCredentials(u.User)
	}

	if shouldConcealHost(u) {
		cloned.Scheme = ""
		cloned.Host = ""
	}

	return cloned.String()
}

// Since logs are rendered to the public, we should obfuscate the Dependabot's
// API hostnames. We can make an exception for AWS runners as those logs are
// scrubbed at runtime.
func shouldConcealHost(url *url.URL) bool {
	// pass through calls to the backend from AWS runners
	if url.Hostname() == "dependabot-api.githubapp.com" {
		return false
	}

	if strings.HasPrefix(url.Hostname(), "dependabot-api") || strings.HasPrefix(url.Hostname(), "dependabot-actions") {
		return true
	}

	return false
}

func userWithoutCredentials(user *url.Userinfo) *url.Userinfo {
	username := ""
	if user.Username() != "" {
		username = placeholder
	}

	password, ok := user.Password()
	if !ok {
		return url.User(username)
	}
	if password != "" {
		return url.UserPassword(username, placeholder)
	}
	return url.UserPassword(username, "")
}

type Formatter struct{}

func (f *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("%s %s\n", entry.Time.UTC().Format("2006/01/02 15:04:05"), entry.Message)), nil
}

func setupLogging() *os.File {
	logrus.SetFormatter(&Formatter{})

	if logfilePath != nil && *logfilePath != "" && *logfilePath != "-" {

		file, err := os.OpenFile(*logfilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal("Failed to open log file: ", err)
		}
		log.SetOutput(file)
		logrus.SetOutput(file)
		return file
	}
	return nil
}
