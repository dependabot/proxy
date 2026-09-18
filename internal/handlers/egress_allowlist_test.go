package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// TestEgressAllowlist_DashCasedExperimentKeys guards the dash/underscore key
// contract with the API. The API serializes experiments through the JSON:API
// adapter (default key transform: dash), so the observe/enforce flags arrive in
// the job-details payload as "proxy-egress-observe"/"proxy-egress-enforce". The
// constants must match those literal keys, otherwise the flags never activate.
func TestEgressAllowlist_DashCasedExperimentKeys(t *testing.T) {
	require.Equal(t, "proxy-egress-observe", egressObserveExperiment)
	require.Equal(t, "proxy-egress-enforce", egressEnforceExperiment)

	experiments := config.Experiments{
		"proxy-egress-observe": true,
		"proxy-egress-enforce": false,
	}
	assert.True(t, experiments.Enabled("proxy-egress-observe"), "dash-keyed observe flag is enabled")
	assert.False(t, experiments.Enabled("proxy-egress-enforce"))
	assert.False(t, experiments.Enabled("proxy_egress_observe"), "underscore key does not match the forwarded dash key")

	// A handler built from the dash-keyed payload logs but does not block.
	h := NewEgressAllowlistHandler(&config.Config{Experiments: experiments}, config.ProxyEnvSettings{}, nil)
	assert.Nil(t, egressResult(t, h, "https://evil.com/steal"), "observe mode allows the request through")
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

func TestEgressAllowlist_GlobMatchesScopedStorageHosts(t *testing.T) {
	// "*vsblobprod*.blob.core.windows.net" is a glob entry scoped to the
	// non-user-registerable "vsblobprod" infix, so real NuGet/pip CDN backends
	// match, but an arbitrary storage account under the shared parent domain
	// (and a name lacking the infix) must still be blocked.
	h := newEgressHandler(false, true, "nuget")

	assert.Nil(t, egressResult(t, h, "https://ajhvsblobprodcus363.blob.core.windows.net/pkg.nupkg"), "vsblobprod CDN backend allowed")
	assert.Nil(t, egressResult(t, h, "https://ajhvsblobprodcus363.vsblob.vsassets.io/pkg"), "vsassets artifact backend allowed")
	assert.Nil(t, egressResult(t, h, "https://nugetregistryv2prod.blob.core.windows.net/pkg"), "exact CDN host allowed")

	for _, blocked := range []string{
		"https://attacker.blob.core.windows.net/loot",             // shared parent must not be wildcarded
		"https://nugetregistryv2prodx.blob.core.windows.net/loot", // exact entry does not extend to lookalikes
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "unscoped storage host must be blocked: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

func TestEgressAllowlist_GlobScopedFixedComponentsRejectSpoofs(t *testing.T) {
	h := newEgressHandler(false, true, "docker")

	// ECR: only a numeric account label (the "[0-9]*" component) is allowed.
	assert.Nil(t, egressResult(t, h, "https://089022728777.dkr.ecr.us-east-1.amazonaws.com/v2/image"), "numeric ECR account allowed")
	resp := egressResult(t, h, "https://evil.dkr.ecr.us-east-1.amazonaws.com/v2/image")
	if assert.NotNil(t, resp, "non-numeric ECR account label must be blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}

	// CodeArtifact endpoints carry a "-<account>" numeric suffix on the domain label.
	assert.Nil(t, egressResult(t, h, "https://my-repo-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/pkg"), "codeartifact endpoint allowed")
}

func TestEgressAllowlist_SharedRegistryDomainsAllowed(t *testing.T) {
	// Shared third-party registry providers are applied to every job regardless
	// of package manager.
	h := newEgressHandler(false, true, "maven")

	for _, allowed := range []string{
		"https://mycompany.jfrog.io/artifactory/repo",
		"https://mycompany.cloudsmith.io/owner/repo",
		"https://myorg.pkgs.visualstudio.com/_packaging/feed",
		"https://pkgs.dev.azure.com/org/_packaging/feed",
		"https://myfeed.myget.org/F/feed/api",
		"https://jitpack.io/com/example/lib",
		"https://artifactory.internal.cba/repo",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "shared registry host allowed: "+allowed)
	}
}

func TestEgressAllowlist_JFrogS3BucketsAllowedButSharedS3Blocked(t *testing.T) {
	h := newEgressHandler(false, true, "maven")

	// JFrog-owned regional buckets are exact entries and must be allowed.
	for _, allowed := range []string{
		"https://jfrog-prod-euw1-shared-ireland-main.s3.amazonaws.com/artifact",
		"https://jfrog-prod-usw2-shared-oregon-main.s3.amazonaws.com/artifact",
		"https://jfrog-prod-use1-shared-virginia-main.s3.amazonaws.com/artifact",
		"https://jfrog-prod-use1-dedicated-virginia-main.s3.amazonaws.com/artifact",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "JFrog S3 bucket allowed: "+allowed)
	}

	// The shared S3 namespace must stay blocked: neither an attacker bucket that
	// mimics the JFrog token shape (virtual-hosted) nor path-style access to the
	// bare endpoint may be allowed.
	for _, blocked := range []string{
		"https://jfrog-prod-evil-shared-x-main.s3.amazonaws.com/loot",
		"https://jfrog-prod-evil-dedicated-x-main.s3.amazonaws.com/loot",
		"https://attacker-bucket.s3.amazonaws.com/loot",
		"https://s3.amazonaws.com/attacker-bucket/loot",
		"https://s3-us-west-2.amazonaws.com/attacker-bucket/loot",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "shared S3 host must be blocked: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

func TestEgressAllowlist_NewExactDomainsAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "npm_and_yarn")

	for _, allowed := range []string{
		"https://registry.npmmirror.com/left-pad",
		"https://cdn.npmmirror.com/left-pad/-/left-pad.tgz",
		"https://registry.npmjs.com/left-pad",
		"https://maven.google.com/androidx/pkg.pom",
		"https://packages.drupal.org/8/packages.json",
		"https://packages.confluent.io/maven/pkg.jar",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "new exact host allowed: "+allowed)
	}
}

func TestEgressAllowlist_PublicRegistriesAllowed(t *testing.T) {
	// A representative sample of the curated public registry/CDN/mirror hosts.
	// These are provider-controlled public infrastructure, applied to every job.
	h := newEgressHandler(false, true, "maven")

	for _, allowed := range []string{
		"https://repo.spring.io/artifactory/repo",
		"https://oss.sonatype.org/content/repositories/snapshots",
		"https://repository.apache.org/content/groups/public",
		"https://clojars.org/repo",
		"https://download.pytorch.org/whl/torch.whl",
		"https://pypi.nvidia.com/simple",
		"https://mirrors.aliyun.com/pypi/simple",
		"https://www.nuget.org/api/v2/package",
		"https://hub.docker.com/v2/repositories/library/nginx",
		"https://lscr.io/v2/linuxserver/image",
		"https://wpackagist.org/packages.json",
		"https://go.googlesource.com/tools",
		"https://android.googlesource.com/platform",
		"https://nodejs.org/dist/index.json",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "public registry host allowed: "+allowed)
	}
}

// fakeMetricSender captures the metrics emitted by the egress handler.
type fakeMetricSender struct {
	metrics []sentMetric
}

type sentMetric struct {
	name string
	tags map[string]string
}

func (s *fakeMetricSender) SendMetric(name string, _ string, _ float64, additionalTags map[string]string) error {
	s.metrics = append(s.metrics, sentMetric{name: name, tags: additionalTags})
	return nil
}

func TestEgressAllowlist_RecordsObservedHosts(t *testing.T) {
	sender := &fakeMetricSender{}
	h := NewEgressAllowlistHandler(egressCfg(true, false), config.ProxyEnvSettings{}, sender)

	egressResult(t, h, "https://registry.npmjs.org/left-pad")
	egressResult(t, h, "https://evil.com/steal")

	assert.Equal(t, []sentMetric{
		{name: egressHostMetric, tags: map[string]string{"request_host": "registry.npmjs.org", "allowlisted": "true"}},
		{name: egressHostMetric, tags: map[string]string{"request_host": "evil.com", "allowlisted": "false"}},
	}, sender.metrics)
}

// TestEgressAllowlist_RecordsEnforceBlockedHosts verifies that a host blocked in
// enforce mode is still recorded, since the observation happens before the 403
// short-circuits the request chain.
func TestEgressAllowlist_RecordsEnforceBlockedHosts(t *testing.T) {
	sender := &fakeMetricSender{}
	h := NewEgressAllowlistHandler(egressCfg(false, true), config.ProxyEnvSettings{}, sender)

	resp := egressResult(t, h, "https://evil.com/steal")
	require.NotNil(t, resp, "enforce blocks the host")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	assert.Equal(t, []sentMetric{
		{name: egressHostMetric, tags: map[string]string{"request_host": "evil.com", "allowlisted": "false"}},
	}, sender.metrics, "blocked host is recorded despite the 403")
}

func TestEgressAllowlist_DoesNotRecordWhenDisabled(t *testing.T) {
	sender := &fakeMetricSender{}
	h := NewEgressAllowlistHandler(egressCfg(false, false), config.ProxyEnvSettings{}, sender)

	egressResult(t, h, "https://evil.com/steal")

	assert.Empty(t, sender.metrics, "fail-open mode records nothing")
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
