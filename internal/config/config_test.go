package config

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	cases := map[string]struct {
		input    string
		expected *Config
	}{
		"empty": {
			input:    "{}",
			expected: &Config{},
		},
		"proxy_auth": {
			input:    "{\"proxy_auth\": { \"username\": \"proxy_user\", \"password\": \"password\" }}",
			expected: &Config{ProxyAuth: BasicAuthCredentials{Username: "proxy_user", Password: "password"}},
		},
	}

	temp := t.TempDir()
	for _, fname := range []string{"-", "config_test.json"} {
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				var configPath string
				if fname == "-" {
					configPath = fname
					mockStdin(t, tc.input)
				} else {
					configPath = path.Join(temp, fname)
					d1 := []byte(tc.input)
					err := os.WriteFile(configPath, d1, 0644)
					require.NoError(t, err)
				}

				cfg, err := Parse(configPath)
				require.NoError(t, err)
				assert.Equal(t, tc.expected, cfg)
			})
		}
	}
}

func TestHost(t *testing.T) {
	cases := map[string]struct {
		input    Credential
		expected string
	}{
		"empty": {
			input:    Credential{},
			expected: "",
		},
		"host": {
			input:    Credential{"host": "example.com"},
			expected: "example.com",
		},
		"url": {
			input:    Credential{"url": "https://example.com/path"},
			expected: "example.com",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.input.Host())
		})
	}
}

func mockStdin(t testing.TB, input string) {
	t.Helper()

	oldOsStdin := os.Stdin

	tmpfile, err := os.CreateTemp(t.TempDir(), "input")
	require.NoError(t, err)

	_, err = tmpfile.Write([]byte(input))
	require.NoError(t, err)

	_, err = tmpfile.Seek(0, 0)
	require.NoError(t, err)

	// Set stdin to the temp file
	os.Stdin = tmpfile

	t.Cleanup(func() {
		// reset os.Stdin
		os.Stdin = oldOsStdin
		tmpfile.Close()
	})
}
