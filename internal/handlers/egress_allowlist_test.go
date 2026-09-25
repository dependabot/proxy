package handlers

import (
	"net/http"
	"net/http/httptest"
	"path"
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
	// pkgs.dev.azure.com is an exact entry: a user-controlled subdomain must NOT
	// be allowed, or it becomes an exfiltration channel.
	h := newEgressHandler(false, true, "maven")

	assert.Nil(t, egressResult(t, h, "https://pkgs.dev.azure.com/org/_packaging/feed"), "exact host allowed")

	resp := egressResult(t, h, "https://attacker.pkgs.dev.azure.com/loot")
	if assert.NotNil(t, resp, "user-controlled subdomain must be blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_SharedObjectStorePathStyleTradeoff(t *testing.T) {
	// storage.googleapis.com is allowlisted as an EXACT apex host because public
	// Go (proxy.golang.org) and Dart (pub.dev) downloads redirect there and
	// public jobs have no credentials to reach it otherwise. Accepted risk: the
	// apex reaches every path-style bucket. Virtual-hosted "<bucket>." subdomains
	// are NOT covered by an exact apex entry and must stay blocked.
	h := newEgressHandler(false, true, "go_modules")

	for _, allowed := range []string{
		"https://storage.googleapis.com/proxy-golang-org/x.zip",  // go_modules redirect target
		"https://storage.googleapis.com/dartlang-pub/pkg.tar.gz", // pub redirect target
	} {
		assert.Nil(t, egressResult(t, h, allowed), "path-style apex host must be allowed: "+allowed)
	}

	resp := egressResult(t, h, "https://attacker-bucket.storage.googleapis.com/loot")
	if assert.NotNil(t, resp, "virtual-hosted bucket subdomain must be blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_SuffixEntryAllowsSubdomain(t *testing.T) {
	// .gcr.io is a leading-dot entry, so regional subdomains match.
	h := newEgressHandler(false, true, "docker")

	assert.Nil(t, egressResult(t, h, "https://us.gcr.io/v2/project/image"), "provider-controlled subdomain allowed")
	assert.Nil(t, egressResult(t, h, "https://europe-docker.pkg.dev/v2/project/image"), "artifact registry subdomain allowed")
}

func TestEgressAllowlist_NuGetStorageBackendsAllowed(t *testing.T) {
	// NuGet's per-region Azure Blob / Azure DevOps CDN backends are allowlisted
	// via the "*vsblobprod*" / ".vsblob." globs. These are a KNOWN, accepted
	// exposure (the account label is attacker-choosable), documented in the YAML.
	// The shared parent domain must still not be wildcarded, and the exact entry
	// must not extend to lookalikes.
	h := newEgressHandler(false, true, "nuget")

	for _, allowed := range []string{
		"https://ajhvsblobprodcus363.blob.core.windows.net/pkg.nupkg", // vsblobprod CDN backend
		"https://ajhvsblobprodcus363.vsblob.vsassets.io/pkg",          // vsassets artifact backend
		"https://nugetregistryv2prod.blob.core.windows.net/pkg",       // exact CDN host
	} {
		assert.Nil(t, egressResult(t, h, allowed), "nuget storage backend allowed: "+allowed)
	}

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

func TestEgressAllowlist_MultiTenantAWSNamespacesNotGloballyAllowed(t *testing.T) {
	// A 12-digit AWS account id matches every AWS tenant, so ECR and CodeArtifact
	// are NOT globally allowlisted (an attacker could use their own account).
	// They are blocked by default and only reachable via the job's credentials.
	h := newEgressHandler(false, true, "docker")

	for _, blocked := range []string{
		"https://089022728777.dkr.ecr.us-east-1.amazonaws.com/v2/image",               // real-looking ECR account
		"https://evil.dkr.ecr.us-east-1.amazonaws.com/v2/image",                       // non-numeric label
		"https://my-repo-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/pkg", // real-looking CodeArtifact endpoint
		"https://repo-1evil.d.codeartifact.us-east-1.amazonaws.com/npm/pkg",           // spoofed account label
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "multi-tenant AWS namespace must be blocked by default: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}

	// When the job is configured to use one, its exact ECR host is allowed via
	// the credential-derived dynamic hosts (a different account stays blocked).
	configured := newEgressHandlerWithCreds(config.Credentials{
		{"type": "docker_registry", "registry": "089022728777.dkr.ecr.us-east-1.amazonaws.com"},
	})
	assert.Nil(t, egressResult(t, configured, "https://089022728777.dkr.ecr.us-east-1.amazonaws.com/v2/image"),
		"configured ECR registry allowed exactly via dynamic hosts")
	resp := egressResult(t, configured, "https://999988887777.dkr.ecr.us-east-1.amazonaws.com/v2/image")
	if assert.NotNil(t, resp, "a different AWS account's ECR is still blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestEgressAllowlist_SharedRegistryDomainsAllowed(t *testing.T) {
	// Shared third-party infrastructure with fixed, provider-owned hosts is
	// applied to every job regardless of package manager.
	h := newEgressHandler(false, true, "maven")

	for _, allowed := range []string{
		"https://pkgs.dev.azure.com/org/_packaging/feed",
		"https://jitpack.io/com/example/lib",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "shared registry host allowed: "+allowed)
	}
}

func TestEgressAllowlist_CustomerTenantProvidersAreNotGloballyAllowed(t *testing.T) {
	// Providers whose subdomain is a customer-chosen tenant name must NOT be
	// globally wildcarded: a global "*.<provider>" would allow an attacker-
	// provisioned tenant. They are only reachable when a job is configured to
	// use one (added exactly via credential-derived dynamic hosts).
	h := newEgressHandler(false, true, "maven")

	for _, blocked := range []string{
		"https://attacker.jfrog.io/artifactory/repo",
		"https://attacker.pkgs.visualstudio.com/_packaging/feed",
		"https://attacker.cloudsmith.io/owner/repo",
		"https://attacker.myget.org/F/feed/api",
		"https://artifactory.internal.cba/repo",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "customer-tenant provider must not be globally allowed: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}

	// When the job is configured to use one, the exact host is allowed via the
	// credential-derived dynamic hosts.
	configured := newEgressHandlerWithCreds(config.Credentials{
		{"type": "maven_repository", "url": "https://mycompany.jfrog.io/artifactory/repo"},
	})
	assert.Nil(t, egressResult(t, configured, "https://mycompany.jfrog.io/artifactory/repo"),
		"configured JFrog tenant allowed exactly via dynamic hosts")
	resp := egressResult(t, configured, "https://attacker.jfrog.io/artifactory/repo")
	if assert.NotNil(t, resp, "a different tenant is still blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

// TestEgressAllowlist_DynamicHostsMatchedExactly guards against a
// credential-derived host being treated as a glob pattern. A configured value
// containing glob metacharacters (e.g. "https://*.com") must match nothing
// rather than open enforcement for every ".com" host.
func TestEgressAllowlist_DynamicHostsMatchedExactly(t *testing.T) {
	h := newEgressHandlerWithCreds(config.Credentials{
		{"type": "maven_repository", "url": "https://*.com/repo"},
	})

	resp := egressResult(t, h, "https://evil.com/steal")
	if assert.NotNil(t, resp, "a glob-shaped credential host must not become a wildcard") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
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

// TestEgressAllowlist_ProdBlockedHostsNowAllowed covers the hosts added from
// the production blocked-domain sample. Each is public, provider-controlled
// infrastructure that a job cannot reach via credentials, so blocking it under
// enforce breaks dependency resolution outright.
func TestEgressAllowlist_ProdBlockedHostsNowAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "")

	for name, allowed := range map[string][]string{
		"go vanity imports": {
			"https://buf.build/gen/go/pkg",
			"https://go.uber.org/zap",
			"https://k8s.io/client-go",
			"https://sigs.k8s.io/yaml",
			"https://filippo.io/edwards25519",
			"https://cel.dev/expr",
			"https://connectrpc.com/connect",
			"https://go.etcd.io/bbolt",
			"https://go.mongodb.org/mongo-driver",
			"https://go.starlark.net/starlark",
			"https://go4.org/netipx",
			"https://golang.zx2c4.com/wireguard",
			"https://gorm.io/gorm",
			"https://layeh.com/radius",
			"https://modernc.org/sqlite",
			"https://mvdan.cc/gofumpt",
			"https://olympos.io/encoding/edn",
			"https://rsc.io/quote",
			"https://storj.io/common",
		},
		"public vcs forges": {
			"https://bitbucket.org/team/repo.git/info/refs",
			"https://api.bitbucket.org/2.0/repositories/team/repo",
			"https://codeberg.org/owner/repo.git/info/refs",
			"https://gitea.com/owner/repo.git/info/refs",
			"https://git.sr.ht/~owner/repo",
			"https://gitlab.com/group/project.git/info/refs",
			"https://gitlab.freedesktop.org/group/project",
			"https://foss.heptapod.net/pypy/pypy",
		},
		"jvm repositories": {
			"https://s01.oss.sonatype.org/content/repositories/releases",
			"https://www.jitpack.io/com/example/lib",
			"https://repo.gradle.org/artifactory/libs-releases",
			"https://downloads.gradle.org/distributions/gradle-8.0-bin.zip",
			"https://repo.typesafe.com/typesafe/releases",
			"https://maven.twttr.com/com/twitter/lib.jar",
			"https://build.shibboleth.net/maven/releases",
			"https://maven.enginehub.org/repo",
			"https://maven.canvasmc.io/releases",
			"https://repo.thenextlvl.net/releases",
			"https://cdn.reproio.com/maven/io/repro/sdk.aar",
			"https://build-artifacts.signal.org/maven",
			"https://redirector.kotlinlang.org/maven/artifact.jar",
			"https://developer.huawei.com/repo/agconnect.aar",
			"https://appboy.github.io/appboy-android-sdk/sdk.aar",
		},
		"ecosystem registries and cdns": {
			"https://juliaregistries.github.io/General/registry.toml",
			"https://us-east.pkg.julialang.org/registries",
			"https://us-west.pkg.julialang.org/registries",
			"https://flashinfer.ai/whl/cu121/flashinfer.whl",
			"https://download-r2.pytorch.org/whl/torch.whl",
			"https://builds.hex.pm/builds/elixir/builds.txt",
			"https://npm.jsr.io/@jsr/std__path",
			"https://dl.fontawesome.com/releases/v6/fontawesome.zip",
			"https://mirrors.cloud.tencent.com/gradle/gradle-8.0-bin.zip",
			"https://satis.spatie.be/packages.json",
			"https://download.swift.org/swift-5.9-release/toolchain.tar.gz",
			"https://releases.bazel.build/7.0.0/release/bazel-7.0.0-linux-x86_64",
		},
		"verification and protocol endpoints": {
			"https://checkpoint-api.hashicorp.com/v1/check/terraform",
			"https://crl3.digicert.com/sha2-assured-cs-g1.crl",
			"https://ocsp.digicert.com/",
			"https://oneocsp.microsoft.com/ocsp",
			"https://www.microsoft.com/pkiops/crl/microsoft.crl",
			"https://spsprodcus3.vssps.visualstudio.com/_signin",
			"https://spsproduks1.vssps.visualstudio.com/_signin",
		},
	} {
		for _, target := range allowed {
			assert.Nil(t, egressResult(t, h, target), name+": expected allowed: "+target)
		}
	}
}

// TestEgressAllowlist_NewEntriesDoNotWidenBeyondExactHosts guards the safety
// boundaries documented alongside the §A additions. Every new entry is an exact
// host, so neither a sibling name nor a CHILD subdomain may inherit it.
//
// The two probe families are distinct and both are required:
//   - Child probes ("evil.<entry>") fail if an entry is relaxed to the
//     leading-dot suffix form (".appboy.github.io"). This is the suffix
//     regression the exact-host convention exists to prevent.
//   - Sibling probes ("attacker.<parent-of-entry>") fail if an entry is
//     widened to its parent namespace ("*.github.io"), which a child probe
//     alone would not catch.
func TestEgressAllowlist_NewEntriesDoNotWidenBeyondExactHosts(t *testing.T) {
	h := newEgressHandler(false, true, "")

	// Child hosts of the added exact entries. Each of these starts failing the
	// moment its entry is changed to a leading-dot suffix, so this is the probe
	// set that actually pins exact-host semantics.
	childProbes := []string{
		"https://evil.appboy.github.io/payload",
		"https://evil.juliaregistries.github.io/payload",
		"https://evil.spsprodcus3.vssps.visualstudio.com/_signin",
		"https://evil.us-east.pkg.julialang.org/registries",
		"https://evil.crl3.digicert.com/payload",
		"https://evil.www.microsoft.com/pkiops/crl/x.crl",
		"https://evil.s01.oss.sonatype.org/content/repositories",
		"https://evil.build-artifacts.signal.org/maven",
		"https://evil.redirector.kotlinlang.org/maven",
		"https://evil.buf.build/payload",
		"https://evil.flashinfer.ai/whl/x.whl",
		"https://evil.bitbucket.org/team/repo",
		"https://evil.codeberg.org/owner/repo",
		"https://evil.gitlab.com/group/project",
		"https://evil.releases.bazel.build/payload",
	}

	// Sibling hosts: names sharing a parent with an added entry. These pin the
	// parent namespace closed ("*.github.io", "*.vssps.visualstudio.com").
	siblingProbes := []string{
		"https://attacker.github.io/payload",
		"https://attacker.vssps.visualstudio.com/_signin",
		"https://attacker.pkg.julialang.org/registries",
		"https://attacker.digicert.com/payload",
		"https://attacker.bazel.build/payload",
		// Cloudsmith is multi-tenant with the tenant in the URL path, and the
		// allowlist authorizes the hostname only. Neither the tenant subdomain
		// form nor the shared download hosts may be globally allowed.
		"https://attacker.cloudsmith.io/owner/repo",
		"https://dl.cloudsmith.io/token/org/repo/maven/artifact.jar",
		"https://npm.cloudsmith.io/org/repo/left-pad",
		// SourceForge was not added: the sampled traffic was POM metadata, and
		// the real clone/download chain (git.code.sf.net, downloads. and
		// *.dl.sourceforge.net mirrors) is user-uploadable file hosting.
		"https://sourceforge.net/projects/proj/files",
		"https://downloads.sourceforge.net/project/proj/file.zip",
	}

	for _, blocked := range append(childProbes, siblingProbes...) {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "new entries must not widen to: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
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
		{name: egressHostMetric, tags: map[string]string{"request_host": "registry.npmjs.org", "allowlisted": "true", "block_enforced": "false"}},
		{name: egressHostMetric, tags: map[string]string{"request_host": "evil.com", "allowlisted": "false", "block_enforced": "false"}},
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
		{name: egressHostMetric, tags: map[string]string{"request_host": "evil.com", "allowlisted": "false", "block_enforced": "true"}},
	}, sender.metrics, "blocked host is recorded despite the 403")
}

// TestEgressAllowlist_BlockEnforcedTagDistinguishesObserveFromEnforce verifies
// the block_enforced tag separates an enforce-mode 403 from an observe-only host
// that is logged but still permitted (both carry allowlisted=false).
func TestEgressAllowlist_BlockEnforcedTagDistinguishesObserveFromEnforce(t *testing.T) {
	// Observe only: not allowlisted, logged, but allowed through -> block_enforced=false.
	observeSender := &fakeMetricSender{}
	observe := NewEgressAllowlistHandler(egressCfg(true, false), config.ProxyEnvSettings{}, observeSender)
	assert.Nil(t, egressResult(t, observe, "https://evil.com/steal"), "observe permits the host")
	assert.Equal(t, []sentMetric{
		{name: egressHostMetric, tags: map[string]string{"request_host": "evil.com", "allowlisted": "false", "block_enforced": "false"}},
	}, observeSender.metrics)

	// Observe + enforce: not allowlisted and dropped -> block_enforced=true.
	enforceSender := &fakeMetricSender{}
	enforce := NewEgressAllowlistHandler(egressCfg(true, true), config.ProxyEnvSettings{}, enforceSender)
	resp := egressResult(t, enforce, "https://evil.com/steal")
	require.NotNil(t, resp, "enforce blocks the host")
	assert.Equal(t, []sentMetric{
		{name: egressHostMetric, tags: map[string]string{"request_host": "evil.com", "allowlisted": "false", "block_enforced": "true"}},
	}, enforceSender.metrics)
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

func TestEgressAllowlist_AddedMissingDomainsAllowed(t *testing.T) {
	// Newly added public, provider/project-controlled hosts. The handler applies
	// the union of all ecosystem defaults, so any package manager may reach them.
	h := newEgressHandler(false, true, "docker")

	for _, allowed := range []string{
		"https://hub.docker.com/v2/repositories/library/nginx",
		"https://production.cloudfront.docker.com/registry-v2/blob",
		"https://go.googlesource.com/tools",
		"https://golang.org/x/tools",
		"https://google.golang.org/grpc",
		"https://go.opentelemetry.io/otel",
		"https://gopkg.in/yaml.v3",
		"https://go.yaml.in/yaml/v3",
		"https://maven.google.com/androidx/pkg.pom",
		"https://repo.broadcom.com/artifactory/repo",
		"https://builds.dotnet.microsoft.com/dotnet/Sdk/x.zip",
		"https://ci.dot.net/public/dotnet/x.nupkg",
		"https://charts.bitnami.com/bitnami/index.yaml",
		"https://charts.jetstack.io/charts/cert-manager.tgz",
		"https://prometheus-community.github.io/helm-charts/index.yaml",
		"https://grafana.github.io/helm-charts/index.yaml",
		"https://jaegertracing.github.io/helm-charts/index.yaml",
		"https://cocoapods.org/pods/AFNetworking",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "added host should be allowed: "+allowed)
	}

	// A user-controlled GitHub Pages host that is NOT one of the exact chart
	// repos must still be blocked (no "*.github.io" wildcard was introduced).
	resp := egressResult(t, h, "https://attacker.github.io/loot")
	if assert.NotNil(t, resp, "arbitrary github.io host must be blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestValidateGlobPattern(t *testing.T) {
	valid := []string{
		"*.example.com",
		"*-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].d.codeartifact.*.amazonaws.com",
		"[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].dkr.ecr.*.amazonaws.com",
		"[a-z0-9]*.example.com",
		"host?.example.com",
		"[^x]host.example.com",
	}
	for _, p := range valid {
		assert.NoErrorf(t, validateGlobPattern(p), "expected %q to be a valid glob", p)
		// path.Match must agree it is a well-formed pattern (no ErrBadPattern).
		_, err := path.Match(p, "probe.example.com")
		assert.NoErrorf(t, err, "path.Match disagrees on validity of %q", p)
	}

	invalid := []string{
		"foo*bar[", // unterminated class after a literal path.Match never reaches
		"[",        // bare unterminated class
		"[]",       // empty class
		"a[b-",     // range with missing high bound / unterminated
		"pre[abc",  // unterminated class with content
	}
	for _, p := range invalid {
		assert.Errorf(t, validateGlobPattern(p), "expected %q to be rejected", p)
	}
}

// TestEgressDefaults_AliasedEcosystemsStayInSync guards the YAML anchor/alias
// pattern used to de-duplicate ecosystems that share a registry set
// (npm_and_yarn/bun, pip/uv, maven/gradle, docker/docker_compose/devcontainers).
//
// The alias makes the duplication impossible by construction, so this test
// exists to catch the regression where someone expands one member back into a
// literal list and edits only that copy. It asserts equality including order,
// since an alias always yields the identical sequence.
func TestEgressDefaults_AliasedEcosystemsStayInSync(t *testing.T) {
	for _, group := range [][]string{
		{"npm_and_yarn", "bun"},
		{"pip", "uv"},
		{"maven", "gradle"},
		{"docker", "docker_compose", "devcontainers"},
	} {
		base := group[0]
		require.NotEmpty(t, ecosystemDefaultDomains[base], "%s must be populated", base)
		for _, other := range group[1:] {
			assert.Equal(t, ecosystemDefaultDomains[base], ecosystemDefaultDomains[other],
				"%s must stay identical to %s (they share a YAML anchor)", other, base)
		}
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
