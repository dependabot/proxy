package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

func newEgressHandler(observe, enforce bool, packageManager string) *EgressAllowlistHandler {
	return NewEgressAllowlistHandler(egressCfg(observe, enforce), config.ProxyEnvSettings{PackageManager: packageManager}, nil)
}

// egressCfg builds a Config whose experiments toggle the egress observe/enforce
// flags.
func egressCfg(observe, enforce bool) *config.Config {
	return &config.Config{
		Experiments: config.Experiments{
			egressObserveExperiment: observe,
			egressEnforceExperiment: enforce,
		},
	}
}

// newEgressHandlerWithCreds builds an enforce-mode handler whose config carries
// the given credentials, so dynamic-host derivation can be exercised.
func newEgressHandlerWithCreds(creds config.Credentials) *EgressAllowlistHandler {
	cfg := egressCfg(false, true)
	cfg.Credentials = creds
	return NewEgressAllowlistHandler(cfg, config.ProxyEnvSettings{}, nil)
}

// egressResult runs HandleRequest and returns the response (nil means allowed).
func egressResult(t *testing.T, h *EgressAllowlistHandler, rawURL string) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	_, resp := h.HandleRequest(req, nil)
	if resp != nil && resp.Body != nil {
		t.Cleanup(func() { mustClose(resp.Body) })
	}
	return resp
}

func TestEgressAllowlist_FailOpenWhenDisabled(t *testing.T) {
	h := newEgressHandler(false, false, "npm_and_yarn")

	assert.Nil(t, egressResult(t, h, "https://evil.com/steal"), "both flags off allows everything")
}

func TestEgressAllowlist_ObserveAllowsButDoesNotBlock(t *testing.T) {
	h := newEgressHandler(true, false, "npm_and_yarn")

	assert.Nil(t, egressResult(t, h, "https://registry.npmjs.org/left-pad"), "allowlisted host passes")
	assert.Nil(t, egressResult(t, h, "https://evil.com/steal"), "non-allowlisted host is logged but allowed")
}

func TestEgressAllowlist_EnforceBlocksNonAllowlisted(t *testing.T) {
	h := newEgressHandler(false, true, "npm_and_yarn")

	assert.Nil(t, egressResult(t, h, "https://registry.npmjs.org/left-pad"), "allowlisted host passes")

	resp := egressResult(t, h, "https://evil.com/steal")
	if assert.NotNil(t, resp, "non-allowlisted host is blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_ObserveAndEnforceBlocks(t *testing.T) {
	h := newEgressHandler(true, true, "npm_and_yarn")

	resp := egressResult(t, h, "https://evil.com/steal")
	if assert.NotNil(t, resp, "observe+enforce still blocks") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_GitHubInfraAlwaysAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "npm_and_yarn")

	for _, host := range []string{
		"https://github.com/dependabot/proxy",
		"https://api.github.com/repos/dependabot/proxy",
		"https://codeload.github.com/dependabot/proxy",
		"https://objects.githubusercontent.com/blob",
		"https://api.acme.ghe.com/repos/x/y",
	} {
		assert.Nilf(t, egressResult(t, h, host), "github infra allowed: %s", host)
	}
}

func TestEgressAllowlist_UnionAllowsAllEcosystemDefaults(t *testing.T) {
	// The handler applies the union of every ecosystem's defaults, so a pip job
	// may reach npm's registry and vice versa. Partitioning by PACKAGE_MANAGER
	// is intentionally not done.
	h := newEgressHandler(false, true, "pip")

	assert.Nil(t, egressResult(t, h, "https://pypi.org/simple/requests/"), "pip index allowed")
	assert.Nil(t, egressResult(t, h, "https://files.pythonhosted.org/packages/x.whl"), "pip CDN host allowed")
	assert.Nil(t, egressResult(t, h, "https://registry.npmjs.org/left-pad"), "other-ecosystem default also allowed under union")

	resp := egressResult(t, h, "https://evil.com/steal")
	if assert.NotNil(t, resp, "unknown host still blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_ExactEntryRejectsSubdomain(t *testing.T) {
	// storage.googleapis.com is an exact entry: a user-created bucket reachable
	// as <bucket>.storage.googleapis.com must NOT be allowed, or it becomes an
	// exfiltration channel.
	h := newEgressHandler(false, true, "go_modules")

	assert.Nil(t, egressResult(t, h, "https://storage.googleapis.com/proxy-golang-org/x.zip"), "exact object-store host allowed")

	resp := egressResult(t, h, "https://attacker-bucket.storage.googleapis.com/loot")
	if assert.NotNil(t, resp, "user-controlled bucket subdomain must be blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_SuffixEntryAllowsSubdomain(t *testing.T) {
	// .gcr.io is a leading-dot entry, so regional subdomains match.
	h := newEgressHandler(false, true, "docker")

	assert.Nil(t, egressResult(t, h, "https://us.gcr.io/v2/project/image"), "provider-controlled subdomain allowed")
	assert.Nil(t, egressResult(t, h, "https://europe-docker.pkg.dev/v2/project/image"), "artifact registry subdomain allowed")
}

// fakeRecorder records the hosts passed to RecordHost for assertions.
type fakeRecorder struct {
	hosts []recordedHost
}

type recordedHost struct {
	host        string
	allowlisted bool
}

func (r *fakeRecorder) RecordHost(host string, allowlisted bool) {
	r.hosts = append(r.hosts, recordedHost{host: host, allowlisted: allowlisted})
}

func TestEgressAllowlist_RecordsObservedHosts(t *testing.T) {
	recorder := &fakeRecorder{}
	h := NewEgressAllowlistHandler(egressCfg(true, false), config.ProxyEnvSettings{}, recorder)

	egressResult(t, h, "https://registry.npmjs.org/left-pad")
	egressResult(t, h, "https://evil.com/steal")

	assert.Equal(t, []recordedHost{
		{host: "registry.npmjs.org", allowlisted: true},
		{host: "evil.com", allowlisted: false},
	}, recorder.hosts)
}

func TestEgressAllowlist_DoesNotRecordWhenDisabled(t *testing.T) {
	recorder := &fakeRecorder{}
	h := NewEgressAllowlistHandler(egressCfg(false, false), config.ProxyEnvSettings{}, recorder)

	egressResult(t, h, "https://evil.com/steal")

	assert.Empty(t, recorder.hosts, "fail-open mode records nothing")
}

func TestEgressAllowlist_UnknownOrEmptyPackageManagerStillGetsUnion(t *testing.T) {
	// The allowlist does not depend on PACKAGE_MANAGER: an unknown or empty
	// value still yields GitHub infra + the full ecosystem union.
	for _, pm := range []string{"does_not_exist", ""} {
		h := newEgressHandler(false, true, pm)

		assert.Nilf(t, egressResult(t, h, "https://github.com/x/y"), "github infra allowed (pm=%q)", pm)
		assert.Nilf(t, egressResult(t, h, "https://registry.npmjs.org/left-pad"), "npm default allowed under union (pm=%q)", pm)
		assert.Nilf(t, egressResult(t, h, "https://pypi.org/simple/requests/"), "pypi default allowed under union (pm=%q)", pm)

		resp := egressResult(t, h, "https://evil.com/steal")
		if assert.NotNilf(t, resp, "unknown host blocked (pm=%q)", pm) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

func TestEgressAllowlist_LabelBoundaryGuard(t *testing.T) {
	h := newEgressHandler(false, true, "npm_and_yarn")

	resp := egressResult(t, h, "https://evilnpmjs.org/steal")
	if assert.NotNil(t, resp, "lookalike host must not match npmjs.org") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_ExactMatchAllowsAbsoluteFQDN(t *testing.T) {
	// An absolute DNS name (trailing dot) must match an exact allowlist entry,
	// consistent with the suffix form's boundary handling.
	h := newEgressHandler(false, true, "npm_and_yarn")

	assert.Nil(t, egressResult(t, h, "https://registry.npmjs.org./left-pad"),
		"absolute FQDN form of an exact entry must be allowed")
}

func TestEgressAllowlist_AdditionalEcosystemsAllowDefaults(t *testing.T) {
	cases := map[string]string{
		"sbt":            "https://repo1.maven.org/maven2/x.jar",
		"opentofu":       "https://registry.opentofu.org/v1/modules",
		"elm":            "https://package.elm-lang.org/packages/elm/core/latest",
		"deno":           "https://jsr.io/@std/assert",
		"bazel":          "https://bcr.bazel.build/modules/rules_go",
		"julia":          "https://pkg.julialang.org/registries",
		"rust_toolchain": "https://static.rust-lang.org/dist/channel-rust-1.80.toml",
		"conda":          "https://api.anaconda.org/package/conda-forge/numpy",
		"nix":            "https://channels.nixos.org/nixos-24.05/nixexprs.tar.xz",
		"devcontainers":  "https://mcr.microsoft.com/v2/devcontainers/features/manifests/latest",
	}
	for pkgManager, target := range cases {
		h := newEgressHandler(false, true, pkgManager)
		assert.Nilf(t, egressResult(t, h, target), "%s default host should be allowed", pkgManager)
	}
}

func TestEgressDefaults_LoadedFromYAML(t *testing.T) {
	assert.NotEmpty(t, githubInfraDomains, "github infra domains loaded from YAML")
	assert.NotEmpty(t, ecosystemDefaultDomains, "ecosystem map loaded from YAML")
	assert.NotEmpty(t, allEcosystemDomains, "union computed from YAML")

	// The union must be deduplicated even though several ecosystems share hosts
	// (e.g. npm_and_yarn/bun/deno all list registry.npmjs.org).
	seen := make(map[string]struct{}, len(allEcosystemDomains))
	for _, host := range allEcosystemDomains {
		_, dup := seen[host]
		assert.Falsef(t, dup, "union contains duplicate host %q", host)
		seen[host] = struct{}{}
	}
	assert.Contains(t, allEcosystemDomains, "registry.npmjs.org")
	assert.Contains(t, allEcosystemDomains, "pypi.org")
}
