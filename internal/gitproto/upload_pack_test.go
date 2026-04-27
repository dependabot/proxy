package gitproto

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
		{"uppercase media type (RFC 7231 case-insensitive)", http.MethodPost, "https://github.com/octocat/Hello-World.git/git-upload-pack", "Application/X-Git-Upload-Pack-Request", true},
		{"extra whitespace around parameter", http.MethodPost, "https://github.com/octocat/Hello-World.git/git-upload-pack", ct + " ;   charset=utf-8", true},
		{"GET to upload-pack URL", http.MethodGet, "https://github.com/octocat/Hello-World.git/git-upload-pack", ct, false},
		{"POST to other git path (info/refs)", http.MethodPost, "https://github.com/octocat/Hello-World.git/info/refs", ct, false},
		{"POST to non-git path", http.MethodPost, "https://api.github.com/graphql", "application/json", false},
		{"fake upload-pack path with wrong Content-Type", http.MethodPost, "https://example.com/foo/git-upload-pack", "application/json", false},
		{"upload-pack path with no Content-Type", http.MethodPost, "https://github.com/octocat/Hello-World.git/git-upload-pack", "", false},
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

// Realistic OIDs and pkt-line lengths captured from github.com/octocat/Hello-World.
const (
	oidA  = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
	oidB  = "b1b3f9723831141a31a1a7252a213e216ea76e56"
	oidC  = "b3cbd5bbd7e81436d2eee04537ea2b4c0cad4cdf"
	oidH1 = "553c2077f0edc3d5dc5d17262f6aa498e69d6f8e"
	oidH2 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
)

func TestNormalizeUploadPackBody(t *testing.T) {
	t.Run("agent= drift collapses; haves preserved", func(t *testing.T) {
		body1 := "00a4want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack no-progress ofs-delta deepen-since deepen-not agent=git/2.43.0\n" +
			"0032want " + oidB + "\n0000" +
			"0032have " + oidH1 + "\n0009done\n"
		body2 := "00a3want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack no-progress ofs-delta deepen-since deepen-not agent=git/2.9.5\n" +
			"0032want " + oidB + "\n0000" +
			"0032have " + oidH1 + "\n0009done\n"
		if normalize(body1) != normalize(body2) {
			t.Errorf("normalized bodies differ:\n  %q\n  %q", normalize(body1), normalize(body2))
		}
	})

	t.Run("different haves do not collide", func(t *testing.T) {
		body1 := "0032want " + oidA + "\n0000" + "0032have " + oidH1 + "\n0009done\n"
		body2 := "0032want " + oidA + "\n0000" + "0032have " + oidH2 + "\n0009done\n"
		if normalize(body1) == normalize(body2) {
			t.Error("haves drive the upstream pack and must not collapse")
		}
	})

	t.Run("different wants do not collide", func(t *testing.T) {
		body1 := "0032want " + oidA + "\n0009done\n"
		body2 := "0032want " + oidC + "\n0009done\n"
		if normalize(body1) == normalize(body2) {
			t.Error("different wants must not collide")
		}
	})

	t.Run("response-shaping fields stay distinct", func(t *testing.T) {
		bodies := map[string]string{
			"plain":           "0032want " + oidA + "\n0009done\n",
			"shallow":         "000ddeepen 1\n0032want " + oidA + "\n0009done\n",
			"shallow-deeper":  "000ddeepen 2\n0032want " + oidA + "\n0009done\n",
			"filter-blobless": "0015filter blob:none\n0032want " + oidA + "\n0009done\n",
			"filter-treeless": "0012filter tree:0\n0032want " + oidA + "\n0009done\n",
			"thin-pack-on":    "0080want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.43.0\n0009done\n",
			"thin-pack-off":   "0076want " + oidA + " multi_ack_detailed no-done side-band-64k ofs-delta agent=git/2.43.0\n0009done\n",
		}
		seen := make(map[string]string)
		for name, body := range bodies {
			n := normalize(body)
			if other, ok := seen[n]; ok {
				t.Errorf("collision: %q == %q", name, other)
			}
			seen[n] = name
		}
	})

	t.Run("v2 ls-refs ref-prefix is preserved", func(t *testing.T) {
		body1 := "0014command=ls-refs\n0015agent=git/2.43.0\n001bref-prefix refs/heads/\n0000"
		body2 := "0014command=ls-refs\n0015agent=git/2.43.0\n001aref-prefix refs/tags/\n0000"
		if normalize(body1) == normalize(body2) {
			t.Error("different ref-prefix must not collide")
		}
	})

	t.Run("v2 fetch agent drift collapses", func(t *testing.T) {
		body1 := "0012command=fetch\n001bagent=git/2.43.0-Linux\n0001000ddeepen 1\n0032want " + oidA + "\n0009done\n0000"
		body2 := "0012command=fetch\n001bagent=git/2.53.0-Linux\n0001000ddeepen 1\n0032want " + oidA + "\n0009done\n0000"
		if normalize(body1) != normalize(body2) {
			t.Error("v2 agent drift must not affect normalization")
		}
	})

	t.Run("v1 inline agent stripped, other capabilities kept", func(t *testing.T) {
		body1 := "0080want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.43.0\n0009done\n"
		body2 := "0080want " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.53.0\n0009done\n"
		got := normalize(body1)
		if got != normalize(body2) {
			t.Errorf("agent-only difference must collapse:\n  %q\n  %q", got, normalize(body2))
		}
		if !strings.Contains(got, "thin-pack") || strings.Contains(got, "agent=") {
			t.Errorf("got %q", got)
		}
	})

	t.Run("malformed body returned unchanged", func(t *testing.T) {
		body := []byte("this is not pkt-line data")
		if got := NormalizeUploadPackBody(body); !bytes.Equal(got, body) {
			t.Errorf("got %q", got)
		}
	})

	t.Run("empty body produces empty output", func(t *testing.T) {
		if got := NormalizeUploadPackBody(nil); len(got) != 0 {
			t.Errorf("got %q", got)
		}
	})

	// session-id is a per-invocation UUID added in Git 2.36 (April 2022).
	t.Run("v2 standalone session-id is stripped", func(t *testing.T) {
		body1 := "0012command=fetch\n0015agent=git/2.43.0\n0016session-id=abcdef\n00010032want " + oidA + "\n0009done\n0000"
		body2 := "0012command=fetch\n0015agent=git/2.43.0\n0016session-id=fedcba\n00010032want " + oidA + "\n0009done\n0000"
		got := normalize(body1)
		if got != normalize(body2) || strings.Contains(got, "session-id=") {
			t.Errorf("got %q", got)
		}
	})

	t.Run("v1 inline session-id stripped alongside agent", func(t *testing.T) {
		body1 := "009awant " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.43.0 session-id=aaa-1\n0009done\n"
		body2 := "009awant " + oidA + " multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.53.0 session-id=zzz-2\n0009done\n"
		got := normalize(body1)
		if got != normalize(body2) ||
			strings.Contains(got, "session-id=") || strings.Contains(got, "agent=") ||
			!strings.Contains(got, "thin-pack") {
			t.Errorf("got %q", got)
		}
	})

	// Prefix matching is exact: substrings of stripped tokens must survive.
	t.Run("'haven' and 'session-ids' prefixes are not stripped", func(t *testing.T) {
		body := "000ehaven foo\n0014session-ids=keep\n0009done\n"
		got := normalize(body)
		if !strings.Contains(got, "haven foo") || !strings.Contains(got, "session-ids=keep") {
			t.Errorf("got %q", got)
		}
	})
}
