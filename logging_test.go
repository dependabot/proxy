package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var timestamp = regexp.MustCompile(`\d{4}/\d{2}/{2} \d{2}:\d{2}:\d{2} `)

func TestURLWithoutCredentials(t *testing.T) {
	cases := map[string]struct {
		url      string
		expected string
	}{
		"without authentication": {
			url:      "https://foo.com/bar?baz=foz",
			expected: "https://foo.com/bar?baz=foz",
		},
		"conceal user and password": {
			url:      "https://bob:hunter7@foo.com/bar?baz=foz",
			expected: "https://xxx:xxx@foo.com/bar?baz=foz",
		},
		"doesn't conceal empty passwords": {
			url:      "https://bob:@foo.com/bar",
			expected: "https://xxx:@foo.com/bar",
		},
		"should conceal just a user": {
			url:      "https://bob@foo.com/bar",
			expected: "https://xxx@foo.com/bar",
		},
		"should conceal just a password": {
			url:      "https://:hunter7@foo.com/bar",
			expected: "https://:xxx@foo.com/bar",
		},
		"should pass through Dependabot's backend server address for AWS runners": {
			url:      "https://dependabot-api.githubapp.com:443/update_jobs/214124430/create_pull_request",
			expected: "https://dependabot-api.githubapp.com:443/update_jobs/214124430/create_pull_request",
		},
		"should conceal Dependabot's production backend server address for Actions runners": {
			url:      "https://dependabot-actions.githubapp.com:443/update_jobs/214124430/create_pull_request",
			expected: "/update_jobs/214124430/create_pull_request",
		},
		"should conceal Dependabot's dynamic backend server address": {
			url:      "https://dependabot-api-staffship-01.ghe.com:443/update_jobs/214124430/create_pull_request",
			expected: "/update_jobs/214124430/create_pull_request",
		},
	}

	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			u, err := url.Parse(tc.url)
			require.NoError(t, err)
			filtered := urlWithoutCredentials(u)
			assert.Equal(t, tc.expected, filtered)
			assert.Equal(t, tc.url, u.String(), "modified original")
		})
	}
}

func TestRequestLogger(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://github.com:443", nil)
	require.NoError(t, err)
	p := &goproxy.ProxyCtx{Session: 128}

	cases := map[string]struct {
		setup     func(l *requestLogger)
		teardown  func()
		expected  []string
		multiline bool
	}{
		"nothing": {
			expected: nil,
		},
		"request": {
			setup: func(l *requestLogger) {
				l.logRequest(req, p)
			},
			expected: []string{"[128] GET https://github.com:443"},
		},
		"requests": {
			setup: func(l *requestLogger) {
				l.logRequest(req, p)
				l.logRequest(req, p)
			},
			expected: []string{
				"[128] GET https://github.com:443",
				"[128] GET https://github.com:443",
			},
		},

		"response on 40x": {
			setup: func(l *requestLogger) {
				resp := &http.Response{
					Request:    req,
					StatusCode: http.StatusUnauthorized,
					Header: http.Header{
						"Content-Type": []string{"application/json"},
						"X-FOO":        []string{"1"},
						"X-BAR":        []string{"secret"},
					},
					Body: io.NopCloser(bytes.NewBufferString(
						`{
  "status": 401,
  "message": "Unauthorized"
}`,
					)),
				}
				l.logResponse(resp, p)
			},
			expected: []string{
				"[128] 401 https://github.com:443",
				"[128] Remote response: {",
				"  \"status\": 401,",
				"  \"message\": \"Unauthorized\"",
				"}",
			},
			multiline: true,
		},
	}

	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			if tc.teardown != nil {
				defer tc.teardown()
			}

			var buf bytes.Buffer
			log.SetOutput(&buf)
			l := NewRequestLogger()
			if tc.setup != nil {
				tc.setup(l)
			}

			// Check the suffix of each line, to avoid timestamps
			out := strings.Split(buf.String(), "\n")
			assert.Equal(t, len(tc.expected), len(out)-1)
			for index, line := range tc.expected {
				if assert.Greater(t, len(out), index) {
					assert.True(t, strings.HasSuffix(out[index], line),
						fmt.Sprintf("%s did not have suffix %s", out[index], line))
				}
			}

			// Verify timestamps separately:
			for _, line := range out {
				if len(line) == 0 {
					continue
				}
				// The response body will be logged for 40x responses, multiple lines will be logged but only
				// the first one will have a timestamp. We flag such test cases as
				// multiline and skip the timestamp check below for lines that don't
				// have a timestamp.
				if tc.multiline && !timestamp.MatchString(line) {
					continue
				}
				_, err := time.Parse("2006/01/02 15:04:05", line[:19])
				assert.NoErrorf(t, err, "invalid timestamp: %q", line[:19])
			}
		})
	}
}

func TestSetupLogging(t *testing.T) {
	temp := t.TempDir()
	logFile := path.Join(temp, "test.log")
	logfilePath = &logFile
	t.Cleanup(func() {
		logfilePath = nil
	})

	file := setupLogging()
	log.Print("test [log]")
	logrus.Info("test [logrus]")
	err := file.Close()
	require.NoError(t, err)
	text, err := os.ReadFile(filepath.Clean(logFile))
	require.NoError(t, err)
	assert.Contains(t, string(text), "test [log]")
	assert.Contains(t, string(text), "test [logrus]")
}
