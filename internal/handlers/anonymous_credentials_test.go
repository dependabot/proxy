package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

// Anonymous registries are declared without any credential so that their host
// lands in the per-job egress allowlist. The credential must therefore still be
// present in the job config, which previously caused each handler to attach an
// empty Authorization header ("Bearer " with no value, or Basic base64(":")).
// Nexus and Artifactory reject that outright rather than serving the request
// anonymously, so the request must instead be forwarded untouched.

// TestCredentialIsAnonymous pins which credential shapes count as anonymous.
// The two empty-secret shapes arrive by different routes: an org-level registry
// is serialized with no token key at all, while a repo-level one is serialized
// by dependabot-api as token ":" when neither username nor password is set.
func TestCredentialIsAnonymous(t *testing.T) {
	testCases := []struct {
		name     string
		cred     config.Credential
		expected bool
	}{
		{
			name:     "url only (org-level anonymous)",
			cred:     config.Credential{"type": "npm_registry", "url": "https://nexus.example.net"},
			expected: true,
		},
		{
			name:     "colon token (repo-level anonymous)",
			cred:     config.Credential{"type": "npm_registry", "url": "https://nexus.example.net", "token": ":"},
			expected: true,
		},
		{
			name:     "empty token",
			cred:     config.Credential{"type": "npm_registry", "url": "https://nexus.example.net", "token": ""},
			expected: true,
		},
		{
			name:     "token",
			cred:     config.Credential{"type": "npm_registry", "url": "https://nexus.example.net", "token": "secret"},
			expected: false,
		},
		{
			name:     "username and password",
			cred:     config.Credential{"type": "npm_registry", "url": "https://nexus.example.net", "username": "u", "password": "p"},
			expected: false,
		},
		{
			// A username with no password is a misconfiguration, not an anonymous
			// registry. Treating it as anonymous would silently drop an intended
			// credential, so it stays registered and keeps its existing behaviour.
			name:     "username only is not anonymous",
			cred:     config.Credential{"type": "npm_registry", "url": "https://nexus.example.net", "username": "u"},
			expected: false,
		},
		{
			name:     "auth-key",
			cred:     config.Credential{"type": "hex_repository", "url": "https://hex.example.net", "auth-key": "k"},
			expected: false,
		},
		{
			name:     "key",
			cred:     config.Credential{"type": "hex_organization", "organization": "o", "key": "k"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, credentialIsAnonymous(tc.cred))
		})
	}
}

// TestAnonymousCredentialsAreNotAuthenticated covers every handler that did not
// already skip credential-free entries. Each asserts no Authorization header is
// added at all -- an empty "Bearer " or Basic base64(":") would fail this.
func TestAnonymousCredentialsAreNotAuthenticated(t *testing.T) {
	testCases := []struct {
		name           string
		cred           config.Credential
		target         string
		handlerFactory func(config.Credentials) oidcHandler
	}{
		{
			name:   "npm_registry",
			cred:   config.Credential{"type": "npm_registry", "registry": "https://nexus.example.net/repository/npm-all"},
			target: "https://nexus.example.net/repository/npm-all/some-package",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds, testOIDCClient)
			},
		},
		{
			name:   "composer_repository",
			cred:   config.Credential{"type": "composer_repository", "registry": "https://nexus.example.net/repository/composer"},
			target: "https://nexus.example.net/repository/composer/packages.json",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds, testOIDCClient)
			},
		},
		{
			name:   "helm_registry",
			cred:   config.Credential{"type": "helm_registry", "registry": "https://nexus.example.net/repository/helm"},
			target: "https://nexus.example.net/repository/helm/index.yaml",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHelmRegistryHandler(creds, testOIDCClient)
			},
		},
		{
			name:   "python_index",
			cred:   config.Credential{"type": "python_index", "index-url": "https://nexus.example.net/repository/pypi/simple"},
			target: "https://nexus.example.net/repository/pypi/simple/requests/",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds, testOIDCClient)
			},
		},
		{
			name:   "rubygems_server",
			cred:   config.Credential{"type": "rubygems_server", "url": "https://nexus.example.net/repository/gems"},
			target: "https://nexus.example.net/repository/gems/specs.4.8.gz",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewRubyGemsServerHandler(creds, testOIDCClient)
			},
		},
		{
			name:   "docker_registry",
			cred:   config.Credential{"type": "docker_registry", "registry": "nexus.example.net"},
			target: "https://nexus.example.net/v2/library/alpine/manifests/latest",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, testOIDCClient, nil)
			},
		},
		{
			name:   "nuget_feed",
			cred:   config.Credential{"type": "nuget_feed", "url": "https://nexus.example.net/repository/nuget/index.json"},
			target: "https://nexus.example.net/repository/nuget/index.json",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNugetFeedHandler(creds, testOIDCClient)
			},
		},
		{
			name:   "cargo_registry",
			cred:   config.Credential{"type": "cargo_registry", "url": "https://nexus.example.net/repository/cargo"},
			target: "https://nexus.example.net/repository/cargo/api/v1/crates/serde",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewCargoRegistryHandler(creds, testOIDCClient)
			},
		},
		{
			name:   "terraform_registry",
			cred:   config.Credential{"type": "terraform_registry", "url": "https://nexus.example.net/terraform"},
			target: "https://nexus.example.net/terraform/v1/modules/foo/bar/aws/versions",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewTerraformRegistryHandler(creds, testOIDCClient)
			},
		},
		{
			name:   "pub_repository",
			cred:   config.Credential{"type": "pub_repository", "url": "https://nexus.example.net/pub"},
			target: "https://nexus.example.net/pub/api/packages/http",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPubRepositoryHandler(creds, testOIDCClient)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := tc.handlerFactory(config.Credentials{tc.cred})
			req := httptest.NewRequestWithContext(t.Context(), "GET", tc.target, nil)
			req = handleRequestAndClose(handler, req, nil)
			assertUnauthenticated(t, req, "anonymous "+tc.name+" request")
		})
	}

	// The repo-level anonymous shape arrives as token ":" rather than as a
	// missing key. Several handlers guard only on an empty token, so this shape
	// reaches the request path and becomes Basic base64(":"), "Bearer :", or a
	// raw "Authorization: :" depending on the handler.
	t.Run("colon token", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cred := config.Credential{"token": ":"}
				for k, v := range tc.cred {
					cred[k] = v
				}

				handler := tc.handlerFactory(config.Credentials{cred})
				req := httptest.NewRequestWithContext(t.Context(), "GET", tc.target, nil)
				req = handleRequestAndClose(handler, req, nil)
				assertUnauthenticated(t, req, "colon-token "+tc.name+" request")
			})
		}
	})
}

// TestAnonymousCredentialsStillAuthenticateWhenSecretPresent guards against the
// anonymous skip being too eager: the same handlers must keep authenticating a
// credential that does carry a secret.
func TestAnonymousCredentialsStillAuthenticateWhenSecretPresent(t *testing.T) {
	handler := NewNPMRegistryHandler(config.Credentials{
		config.Credential{
			"type":     "npm_registry",
			"registry": "https://nexus.example.net/repository/npm-all",
			"token":    "s3cret",
		},
	}, testOIDCClient)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://nexus.example.net/repository/npm-all/some-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", "s3cret", "credentialed npm request")
}
