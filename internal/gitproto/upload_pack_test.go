package gitproto

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// normalize is a test helper that runs NormalizeUploadPackBody and returns the
// result as a string for direct comparison.
func normalize(body string) string {
	return string(NormalizeUploadPackBody([]byte(body)))
}

func TestIsUploadPackRequest(t *testing.T) {
	const ct = "application/x-git-upload-pack-request"
	cases := []struct {
		name        string
		method      string
		url         string
		contentType string
		want        bool
	}{
		{"real git POST", http.MethodPost, "https://github.com/octocat/Hello-World.git/git-upload-pack", ct, true},
		{"real git POST with charset parameter", http.MethodPost, "https://github.com/octocat/Hello-World.git/git-upload-pack", ct + "; charset=utf-8", true},
		{"real git POST with uppercase media type", http.MethodPost, "https://github.com/octocat/Hello-World.git/git-upload-pack", "Application/X-Git-Upload-Pack-Request", true},
		{"real git POST with extra whitespace around parameter", http.MethodPost, "https://github.com/octocat/Hello-World.git/git-upload-pack", ct + " ;   charset=utf-8", true},
		{"GET to upload-pack URL", http.MethodGet, "https://github.com/octocat/Hello-World.git/git-upload-pack", ct, false},
		{"POST to other git path (info/refs)", http.MethodPost, "https://github.com/octocat/Hello-World.git/info/refs", ct, false},
		{"POST to non-git path", http.MethodPost, "https://api.github.com/graphql", "application/json", false},
		{"POST to fake upload-pack path with wrong Content-Type", http.MethodPost, "https://example.com/foo/git-upload-pack", "application/json", false},
		{"POST to upload-pack path with no Content-Type", http.MethodPost, "https://github.com/octocat/Hello-World.git/git-upload-pack", "", false},
		{"path ends in git-upload-pack but no leading slash", http.MethodPost, "https://example.com/notgit-upload-pack", ct, false},
		{"path has trailing segment after git-upload-pack", http.MethodPost, "https://github.com/foo.git/git-upload-pack/extra", ct, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, nil)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if got := IsUploadPackRequest(req); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeUploadPackBody(t *testing.T) {
	// All bodies use realistic OIDs and pkt-line lengths captured from
	// github.com/octocat/Hello-World.
	const (
		oidA = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
		oidB = "b1b3f9723831141a31a1a7252a213e216ea76e56"
		oidC = "b3cbd5bbd7e81436d2eee04537ea2b4c0cad4cdf"
		// have OIDs are arbitrary — these pkt-lines are dropped during
		// normalization, so their content is irrelevant to the test.
		oidH1 = "553c2077f0edc3d5dc5d17262f6aa498e69d6f8e"
		oidH2 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	)

	t.Run("same wants, different haves and different-length agents → identical", func(t *testing.T) {
		// The flake fix: real-world drift in `have` lines and `agent=` versions
		// (including different string lengths) must collapse to the same output.
		body1 := "00a4want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack no-progress ofs-delta deepen-since deepen-not agent=git/2.43.0\n" +
			"0032want " + oidB + "\n" +
			"0000" +
			"0032have " + oidH1 + "\n" +
			"0009done\n"
		body2 := "00a3want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack no-progress ofs-delta deepen-since deepen-not agent=git/2.9.5\n" +
			"0032want " + oidB + "\n" +
			"0000" +
			"0032have " + oidH2 + "\n" +
			"0009done\n"
		if normalize(body1) != normalize(body2) {
			t.Errorf("normalized bodies differ:\n  %q\n  %q", normalize(body1), normalize(body2))
		}
	})

	t.Run("different wants → different", func(t *testing.T) {
		body1 := "0032want " + oidA + "\n0009done\n"
		body2 := "0032want " + oidC + "\n0009done\n"
		if normalize(body1) == normalize(body2) {
			t.Error("different wants must not collide")
		}
	})

	t.Run("response-shaping fields are preserved", func(t *testing.T) {
		// Each variant must produce a distinct normalized body. Otherwise a
		// shallow clone could be served from a full-clone cache entry, etc.
		bodies := map[string]string{
			"plain":           "0032want " + oidA + "\n0009done\n",
			"shallow":         "000ddeepen 1\n0032want " + oidA + "\n0009done\n",
			"shallow-deeper":  "000ddeepen 2\n0032want " + oidA + "\n0009done\n",
			"filter-blobless": "0015filter blob:none\n0032want " + oidA + "\n0009done\n",
			"filter-treeless": "0012filter tree:0\n0032want " + oidA + "\n0009done\n",
			"thin-pack-on": "0080want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.43.0\n" +
				"0009done\n",
			"thin-pack-off": "0076want " + oidA + " multi_ack_detailed no-done side-band-64k ofs-delta agent=git/2.43.0\n" +
				"0009done\n",
		}
		seen := make(map[string]string)
		for name, body := range bodies {
			n := normalize(body)
			if other, ok := seen[n]; ok {
				t.Errorf("normalized collision: %q and %q produce the same bytes:\n  %q", name, other, n)
			}
			seen[n] = name
		}
	})

	t.Run("v2 ls-refs preserves ref-prefix differences", func(t *testing.T) {
		body1 := "0014command=ls-refs\n0015agent=git/2.43.0\n001bref-prefix refs/heads/\n0000"
		body2 := "0014command=ls-refs\n0015agent=git/2.43.0\n001aref-prefix refs/tags/\n0000"
		if normalize(body1) == normalize(body2) {
			t.Error("different ref-prefix must not collide")
		}
	})

	t.Run("v2 fetch with same wants different agents → identical", func(t *testing.T) {
		body1 := "0012command=fetch\n001bagent=git/2.43.0-Linux\n0001000ddeepen 1\n0032want " + oidA + "\n0009done\n0000"
		body2 := "0012command=fetch\n001bagent=git/2.53.0-Linux\n0001000ddeepen 1\n0032want " + oidA + "\n0009done\n0000"
		if normalize(body1) != normalize(body2) {
			t.Error("v2 agent drift must not affect normalization")
		}
	})

	t.Run("v1 inline agent stripped, capability bytes preserved", func(t *testing.T) {
		body1 := "0080want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.43.0\n0009done\n"
		body2 := "0080want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.53.0\n0009done\n"
		got1, got2 := normalize(body1), normalize(body2)
		if got1 != got2 {
			t.Errorf("agent-only difference must collapse:\n  %q\n  %q", got1, got2)
		}
		if !strings.Contains(got1, "thin-pack") {
			t.Errorf("non-agent capabilities must be preserved, got %q", got1)
		}
		if strings.Contains(got1, "agent=") {
			t.Errorf("agent= must be removed, got %q", got1)
		}
	})

	t.Run("malformed body returned unchanged", func(t *testing.T) {
		body := []byte("this is not pkt-line data")
		got := NormalizeUploadPackBody(body)
		if !bytes.Equal(got, body) {
			t.Errorf("malformed body must be returned unchanged, got %q", got)
		}
	})

	t.Run("empty body → empty output", func(t *testing.T) {
		if got := NormalizeUploadPackBody(nil); len(got) != 0 {
			t.Errorf("empty body should produce empty output, got %q", got)
		}
	})

	t.Run("non-have payload that begins with 'have' substring is preserved", func(t *testing.T) {
		// Defensive: the prefix check requires "have " (with space). A payload
		// like "haven 123\n" must not be dropped.
		body := "000ehaven foo\n0009done\n"
		got := normalize(body)
		if !strings.Contains(got, "haven foo") {
			t.Errorf("non-have payload was incorrectly stripped: %q", got)
		}
	})

	t.Run("v2 standalone session-id stripped (Git 2.36+ trace2 capability)", func(t *testing.T) {
		// session-id is a per-invocation UUID added in Git 2.36 (April 2022).
		// It is purely informational and must not affect the cache key.
		// Payload "session-id=abcdef\n" = 18 bytes → pkt-line length 0016.
		body1 := "0012command=fetch\n0015agent=git/2.43.0\n" +
			"0016session-id=abcdef\n" +
			"00010032want " + oidA + "\n0009done\n0000"
		body2 := "0012command=fetch\n0015agent=git/2.43.0\n" +
			"0016session-id=fedcba\n" +
			"00010032want " + oidA + "\n0009done\n0000"
		n1, n2 := normalize(body1), normalize(body2)
		if n1 != n2 {
			t.Errorf("session-id drift must not affect normalization:\n  %q\n  %q", n1, n2)
		}
		if strings.Contains(n1, "session-id=") {
			t.Errorf("session-id= must be stripped, got %q", n1)
		}
	})

	t.Run("v1 inline session-id stripped alongside agent", func(t *testing.T) {
		// Newer git clients can include session-id as an inline capability on
		// the first v1 want line. Both volatile tokens must collapse together.
		body1 := "009awant " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.43.0 session-id=aaa-1\n0009done\n"
		body2 := "009awant " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.53.0 session-id=zzz-2\n0009done\n"
		n1, n2 := normalize(body1), normalize(body2)
		if n1 != n2 {
			t.Errorf("inline agent+session-id drift must collapse:\n  %q\n  %q", n1, n2)
		}
		if strings.Contains(n1, "session-id=") || strings.Contains(n1, "agent=") {
			t.Errorf("volatile inline tokens must be removed, got %q", n1)
		}
		if !strings.Contains(n1, "thin-pack") {
			t.Errorf("non-volatile capabilities must be preserved, got %q", n1)
		}
	})

	t.Run("payload that merely starts with 'session-id' substring is preserved", func(t *testing.T) {
		// Same defensive check as for "haven": only an exact "session-id="
		// prefix should trigger drop. A hypothetical future "session-ids=..."
		// argument or a want-line containing the literal text must survive.
		body := "0014session-ids=keep\n0009done\n"
		got := normalize(body)
		if !strings.Contains(got, "session-ids=keep") {
			t.Errorf("non-session-id payload was incorrectly stripped: %q", got)
		}
	})
}
