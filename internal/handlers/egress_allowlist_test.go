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

// fakeMetricSender records SendMetric calls for assertions.
type fakeMetricSender struct {
	calls []fakeMetricCall
}

type fakeMetricCall struct {
	name       string
	metricType string
	value      float64
	tags       map[string]string
}

func (f *fakeMetricSender) SendMetric(name, metricType string, value float64, tags map[string]string) error {
	f.calls = append(f.calls, fakeMetricCall{name: name, metricType: metricType, value: value, tags: tags})
	return nil
}

func newEgressHandlerWithMetrics(observe, enforce bool, packageManager string, m metricSender) *EgressAllowlistHandler {
	return NewEgressAllowlistHandler(egressCfg(observe, enforce), config.ProxyEnvSettings{PackageManager: packageManager}, m)
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

func TestEgressAllowlist_EcosystemDefaults(t *testing.T) {
	h := newEgressHandler(false, true, "pip")

	assert.Nil(t, egressResult(t, h, "https://pypi.org/simple/requests/"), "pip index allowed")
	assert.Nil(t, egressResult(t, h, "https://files.pythonhosted.org/packages/x.whl"), "pip CDN host allowed")

	// npm defaults must not apply when the job is a pip job.
	resp := egressResult(t, h, "https://registry.npmjs.org/left-pad")
	if assert.NotNil(t, resp, "other-ecosystem default is not allowed") {
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

func TestEgressAllowlist_UnknownPackageManagerAllowsOnlyGitHubInfra(t *testing.T) {
	h := newEgressHandler(false, true, "does_not_exist")

	assert.Nil(t, egressResult(t, h, "https://github.com/x/y"), "github infra still allowed")

	resp := egressResult(t, h, "https://registry.npmjs.org/left-pad")
	if assert.NotNil(t, resp, "no ecosystem defaults for unknown package manager") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_LabelBoundaryGuard(t *testing.T) {
	h := newEgressHandler(false, true, "npm_and_yarn")

	resp := egressResult(t, h, "https://evilnpmjs.org/steal")
	if assert.NotNil(t, resp, "lookalike host must not match npmjs.org") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
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
	}
	for pkgManager, target := range cases {
		h := newEgressHandler(false, true, pkgManager)
		assert.Nilf(t, egressResult(t, h, target), "%s default host should be allowed", pkgManager)
	}
}

func TestEgressAllowlist_EmitsMetricForNonAllowlistedHost(t *testing.T) {
	m := &fakeMetricSender{}
	h := newEgressHandlerWithMetrics(true, false, "npm_and_yarn", m)

	assert.Nil(t, egressResult(t, h, "https://evil.example.com/steal"), "observe mode allows but records")

	if assert.Len(t, m.calls, 1, "exactly one metric emitted for a non-allowlisted host") {
		call := m.calls[0]
		assert.Equal(t, "egress_not_allowlisted_count", call.name)
		assert.Equal(t, "increment", call.metricType)
		assert.Equal(t, "evil.example.com", call.tags["request_host"], "real host recorded, not bucketed")
	}
}

func TestEgressAllowlist_DoesNotEmitMetricForAllowlistedHost(t *testing.T) {
	m := &fakeMetricSender{}
	h := newEgressHandlerWithMetrics(true, true, "npm_and_yarn", m)

	assert.Nil(t, egressResult(t, h, "https://registry.npmjs.org/left-pad"), "allowlisted host passes")

	assert.Empty(t, m.calls, "no metric emitted for an allowlisted host")
}

func TestEgressAllowlist_EmitsMetricWhenEnforcing(t *testing.T) {
	m := &fakeMetricSender{}
	h := newEgressHandlerWithMetrics(false, true, "npm_and_yarn", m)

	resp := egressResult(t, h, "https://evil.example.com/steal")
	if assert.NotNil(t, resp, "enforce blocks the host") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}

	if assert.Len(t, m.calls, 1, "metric still emitted when enforcing") {
		assert.Equal(t, "evil.example.com", m.calls[0].tags["request_host"])
	}
}
