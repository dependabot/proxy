package handlers

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
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

func TestEgressAllowlist_GitHubPackagesContentHostsAllowed(t *testing.T) {
	// GitHub Packages serves registry metadata from *.pkg.github.com but
	// 302-redirects the actual package download to a per-ecosystem Azure Blob
	// content host carrying a short-lived SAS token. Blocking the redirect
	// target fails the download even though the registry request succeeded.
	// These four hosts are published under domains.packages in
	// https://api.github.com/meta. They are allowed as EXACT hosts only: an
	// Azure storage account name is globally unique and these are already
	// registered to GitHub, so no attacker can claim them.
	h := newEgressHandler(false, true, "bundler")

	for _, allowed := range []string{
		"https://rubygems.pkg.github.com/github/gems/github-kredz-0.0.4.gem",
		"https://rubygemsregistryv2prod.blob.core.windows.net/gems/x.gem?sig=redacted",
		"https://npmregistryv2prod.blob.core.windows.net/npm/x.tgz?sig=redacted",
		"https://mavenregistryv2prod.blob.core.windows.net/maven/x.jar?sig=redacted",
		"https://nugetregistryv2prod.blob.core.windows.net/nuget/x.nupkg?sig=redacted",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "github packages content host allowed: "+allowed)
	}

	for _, blocked := range []string{
		// Child hosts: these start passing the moment an entry is widened to a
		// leading-dot suffix, so they pin the exact-host semantics.
		"https://evil.rubygemsregistryv2prod.blob.core.windows.net/loot",
		"https://evil.npmregistryv2prod.blob.core.windows.net/loot",
		"https://evil.mavenregistryv2prod.blob.core.windows.net/loot",
		// Lookalike account names must not match.
		"https://rubygemsregistryv2prodx.blob.core.windows.net/loot",
		"https://myrubygemsregistryv2prod.blob.core.windows.net/loot",
		// The shared multi-tenant parent stays closed.
		"https://attacker.blob.core.windows.net/loot",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "packages entries must not widen to: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

func TestEgressAllowlist_PublicVendorOCIRegistriesAllowed(t *testing.T) {
	// Vendor-operated public OCI registries that serve anonymous pulls. Each
	// needs its registry host, its token service, and whatever host its blob
	// downloads redirect to; allowing only the registry fixes tag discovery but
	// still fails the pull.
	h := newEgressHandler(false, true, "docker_compose")

	for _, allowed := range []string{
		"https://docker.getcollate.io/v2/openmetadata/server/tags/list",
		"https://docker.redpanda.com/v2/redpandadata/redpanda/tags/list",
		"https://auth.docker.io/token?service=registry.docker.io", // getcollate's token service
		"https://docker.elastic.co/v2/elasticsearch/elasticsearch/tags/list",
		"https://docker-auth.elastic.co/auth?service=token-service",
		"https://docker-registry-production.d24a988e385e0074d717b6bdaea58f0d.r2.cloudflarestorage.com/docker/registry/v2/blobs/sha256/x/data",
		// Chainguard: registry, same-host token service, and its own R2 account.
		"https://cgr.dev/v2/chainguard/wolfi-base/manifests/latest",
		"https://cgr.dev/token?scope=repository:chainguard/wolfi-base:pull&service=cgr.dev",
		"https://9236a389bd48b984df91adc1bc924620.r2.cloudflarestorage.com/chainguard-images-prod/sha256%3Aabc",
		// Red Hat UBI: anonymous, no token service, blobs land on the Quay CDN.
		"https://registry.access.redhat.com/v2/ubi9/ubi-minimal/tags/list",
		"https://registry.access.redhat.com/v2/ubi9/ubi-minimal/manifests/latest",
		"https://cdn01.quay.io/quayio-production-s3/sha256/33/33f1abc",
		// Kubernetes' official registry: same-host token service, and tags,
		// manifests and blobs 307-redirect to its Artifact Registry mirror.
		"https://registry.k8s.io/v2/coredns/coredns/tags/list",
		"https://registry.k8s.io/v2/coredns/coredns/manifests/v1.14.7",
		"https://registry.k8s.io/token?scope=repository:coredns/coredns:pull&service=registry.k8s.io",
		"https://europe-west8-docker.pkg.dev/v2/k8s-artifacts-prod/images/coredns/coredns/tags/list",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "public vendor OCI host allowed: "+allowed)
	}

	for _, blocked := range []string{
		// Child hosts pin the exact-host semantics.
		"https://evil.docker.elastic.co/v2/",
		"https://evil.docker.getcollate.io/v2/",
		"https://evil.docker-registry-production.d24a988e385e0074d717b6bdaea58f0d.r2.cloudflarestorage.com/loot",
		"https://evil.cgr.dev/v2/",
		"https://evil.registry.access.redhat.com/v2/",
		"https://evil.registry.k8s.io/v2/",
		// The Go vanity-import entry for k8s.io is exact, so the apex and its
		// other subdomains stay closed even with registry.k8s.io allowed.
		"https://attacker.k8s.io/v2/",
		// R2 is multi-tenant: only Elastic's and Chainguard's own account hashes
		// are allowed, never a sibling account or the parent domain.
		"https://evil.9236a389bd48b984df91adc1bc924620.r2.cloudflarestorage.com/loot",
		// R2 is multi-tenant: only Elastic's own account hash is allowed.
		"https://loot.deadbeefdeadbeefdeadbeefdeadbeef.r2.cloudflarestorage.com/loot",
		"https://attacker.r2.cloudflarestorage.com/loot",
		// getcollate fronts Docker Hub through Scarf, which is multi-tenant.
		"https://attacker.docker.scarf.sh/v2/",
		"https://docker.scarf.sh/v2/",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "vendor OCI entries must not widen to: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

// TestEgressAllowlist_QuayCDNSubdomainsAllowed pins the deliberate leading-dot
// entry for Quay. The exact apex entry that preceded it did NOT match the
// cdn01-cdn04.quay.io blob CDN, so pulls from any quay.io-hosted image were
// blocked at the blob step while tag discovery appeared to work.
//
// The leading-dot form is safe here specifically because Quay's tenancy is
// path-based (quay.io/<org>/<repo>): a user cannot provision <name>.quay.io, so
// no matched label is attacker-choosable. Do not copy this to a registry that
// hands out subdomains.
func TestEgressAllowlist_QuayCDNSubdomainsAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "docker")

	for _, allowed := range []string{
		"https://quay.io/v2/prometheus/busybox/tags/list",
		"https://cdn01.quay.io/quayio-production-s3/sha256/33/abc",
		"https://cdn02.quay.io/quayio-production-s3/sha256/33/abc",
		// Quay may add CDN hosts; the suffix form must keep covering them.
		"https://cdn99.quay.io/quayio-production-s3/sha256/33/abc",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "quay host allowed: "+allowed)
	}

	for _, blocked := range []string{
		// The suffix must not be satisfiable by an attacker-registered parent.
		"https://quay.io.attacker.com/v2/",
		"https://evil.quay.io.attacker.com/v2/",
		"https://notquay.io/v2/",
		// Red Hat's authenticated registry is deliberately excluded: it needs a
		// Red Hat login, so it belongs in `registries:`, not the defaults.
		"https://registry.redhat.io/v2/ubi9/ubi-minimal/manifests/latest",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "quay entry must not widen to: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

func TestEgressAllowlist_NodeRuntimeDownloadsAllowed(t *testing.T) {
	// pnpm re-resolves a lockfile-pinned Node runtime (devEngines) by fetching
	// checksums from the Node.js project's unofficial-builds host. Since pnpm
	// 12.6 a 403 there is fatal, so blocking it fails every dependency.
	h := newEgressHandler(false, true, "npm_and_yarn")

	for _, allowed := range []string{
		"https://unofficial-builds.nodejs.org/download/release/v24.20.0/SHASUMS256.txt",
		"https://unofficial-builds.nodejs.org/download/release/v24.20.0/node-v24.20.0-linux-x64-musl.tar.xz",
		"https://nodejs.org/dist/v24.20.0/SHASUMS256.txt",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "node runtime download allowed: "+allowed)
	}

	for _, blocked := range []string{
		// Both entries are exact; neither opens the nodejs.org namespace.
		"https://evil.unofficial-builds.nodejs.org/payload",
		"https://attacker.nodejs.org/payload",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "node entries must not widen to: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}

	// These entries live under npm_and_yarn, but every job gets the union of all
	// ecosystem defaults, so a Go job still reaches them.
	goJob := newEgressHandler(false, true, "go_modules")
	assert.Nil(t, egressResult(t, goJob, "https://nodejs.org/dist/index.json"),
		"nodejs.org must stay reachable from a go_modules job")
}

// TestEgressAllowlist_PublicEcosystemMirrorsAllowed covers the public hosts
// recorded as blocked during the 25% enforce rollout. Each is anonymous,
// provider-controlled package infrastructure with no attacker-choosable label.
func TestEgressAllowlist_PublicEcosystemMirrorsAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "")

	for _, allowed := range []string{
		// Legacy NuGet host: Microsoft-owned, every path 404s. Allowed so the
		// client sees a 404 it handles rather than a proxy block it does not.
		"https://data.nuget.org/packages/",
		// Maven Central's Google-hosted mirror.
		"https://maven-central.storage.googleapis.com/maven2/org/slf4j/slf4j-api/maven-metadata.xml",
		"https://maven-central.storage-download.googleapis.com/maven2/org/slf4j/slf4j-api/maven-metadata.xml",
		"https://repo.osgeo.org/repository/release/org/geotools/gt-main/30.0/gt-main-30.0.pom",
		"https://androidx.dev/snapshots/latest/artifacts/repository/androidx/core/core/maven-metadata.xml",
		// packages.atlassian.com 301s to maven.artifacts.atlassian.com, so both
		// ends of the chain must be allowed for a restore to complete.
		"https://packages.atlassian.com/maven/",
		"https://maven.artifacts.atlassian.com/",
		"https://julialang-s3.julialang.org/bin/linux/x64/1.10/julia-1.10.0-linux-x86_64.tar.gz",
		"https://mirrors.huaweicloud.com/repository/npm/lodash",
		"https://pkg.pr.new/tinylibs/tinybench@a832a55",
		// Maven Central's EU download mirror, a sibling of the buckets above.
		"https://maven-central-eu.storage-download.googleapis.com/maven2/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.pom",
		// Vaadin release/add-on repositories.
		"https://maven.vaadin.com/vaadin-addons/org/vaadin/artur/a-vaadin-helper/maven-metadata.xml",
		"https://maven.vaadin.com/vaadin-releases/com/vaadin/flow-server/maven-metadata.xml",
		// Mojang library host used by Minecraft mod builds.
		"https://libraries.minecraft.net/com/mojang/brigadier/1.0.18/brigadier-1.0.18.jar",
		// Backstage version manifests.
		"https://versions.backstage.io/v1/tags/main/manifest.json",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "public ecosystem host allowed: "+allowed)
	}

	// The maven-central entries are exact virtual-hosted buckets. Adding them
	// must not make any other bucket reachable as a subdomain, which is the one
	// way this change could regress the storage.googleapis.com apex exception.
	for _, blocked := range []string{
		"https://attacker.storage.googleapis.com/payload",
		"https://attacker.storage-download.googleapis.com/payload",
		"https://evil.maven-central.storage.googleapis.com/payload",
		"https://evil.maven-central-eu.storage-download.googleapis.com/payload",
		// The new vendor entries are exact hosts: no child may inherit them,
		// and no lookalike parent may match them.
		"https://evil.maven.vaadin.com/payload",
		"https://maven.vaadin.com.attacker.com/payload",
		"https://vaadin.com/payload",
		"https://evil.libraries.minecraft.net/payload",
		"https://libraries.minecraft.net.attacker.com/payload",
		"https://evil.versions.backstage.io/payload",
		"https://backstage.io/payload",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "exact entries must not widen: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}

	// Cloudsmith stays blocked: it is the documented precedent for a shared
	// host whose tenant lives in the path and whose request logs are visible to
	// the tenant. Adding public mirrors must not erode that rule.
	resp := egressResult(t, h, "https://dl.cloudsmith.io/org/repo/npm/left-pad")
	if assert.NotNil(t, resp, "dl.cloudsmith.io must stay blocked") {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
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
		"https://evil.docker.redpanda.com/payload",
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
		"https://evil.data.nuget.org/payload",
		"https://evil.repo.osgeo.org/repository",
		"https://evil.androidx.dev/snapshots",
		"https://evil.pkg.pr.new/owner/repo",
		"https://evil.julialang-s3.julialang.org/bin",
		"https://evil.maven.artifacts.atlassian.com/maven",
		"https://evil.mirrors.huaweicloud.com/repository/npm",
		"https://evil.dotnetcli.blob.core.windows.net/payload",
	}

	// Sibling hosts: names sharing a parent with an added entry. These pin the
	// parent namespace closed ("*.github.io", "*.vssps.visualstudio.com").
	siblingProbes := []string{
		"https://attacker.github.io/payload",
		"https://attacker.vssps.visualstudio.com/_signin",
		"https://attacker.pkg.julialang.org/registries",
		"https://attacker.digicert.com/payload",
		"https://attacker.bazel.build/payload",
		"https://attacker.nuget.org/payload",
		"https://attacker.osgeo.org/repository",
		"https://attacker.artifacts.atlassian.com/maven",
		"https://attacker.huaweicloud.com/repository/npm",
		"https://attacker.julialang.org/bin",
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
		"https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json",
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

func TestEgressDefaults_RegistryRedirectDerivationsLoadedFromYAML(t *testing.T) {
	require.NotEmpty(t, registryRedirectDerivations, "derivations loaded from YAML")

	// The embedded defaults must satisfy the rules enforced at startup.
	assert.NoError(t, validateRegistryRedirectDerivations(registryRedirectDerivations))

	assert.Equal(t, []string{"d3fo0g5hm7lbuv.cloudfront.net"},
		registryRedirectHosts([]string{"packagecloud.io"}))
	assert.Equal(t,
		[]string{
			"gemfury.s3-accelerate.dualstack.amazonaws.com",
			"gemfury.s3-accelerate.amazonaws.com",
		},
		registryRedirectHosts([]string{"pypi.fury.io"}))
}

func TestValidateRegistryRedirectDerivations_RejectsUnmatchableEntries(t *testing.T) {
	// Derived hosts join the dynamic hosts, which are matched exactly, so a glob
	// or leading-dot entry would silently never match.
	cases := map[string]registryRedirectDerivation{
		"empty credential host":     {CredentialHost: "", Derived: []string{"cdn.example.com"}},
		"bare dot credential host":  {CredentialHost: ".", Derived: []string{"cdn.example.com"}},
		"glob credential host":      {CredentialHost: "*.example.com", Derived: []string{"cdn.example.com"}},
		"no derived hosts":          {CredentialHost: "example.com"},
		"empty derived host":        {CredentialHost: "example.com", Derived: []string{""}},
		"glob derived host":         {CredentialHost: "example.com", Derived: []string{"*.cdn.example.com"}},
		"leading-dot derived host":  {CredentialHost: "example.com", Derived: []string{".cdn.example.com"}},
		"glob in second derivation": {CredentialHost: "example.com", Derived: []string{"cdn.example.com", "cdn[.example.com"}},
	}
	for name, derivation := range cases {
		assert.Errorf(t, validateRegistryRedirectDerivations([]registryRedirectDerivation{derivation}),
			"must be rejected: %s", name)
	}

	assert.NoError(t, validateRegistryRedirectDerivations([]registryRedirectDerivation{
		{CredentialHost: "example.com", Derived: []string{"cdn.example.com"}},
		{CredentialHost: ".example.org", Derived: []string{"cdn1.example.org", "cdn2.example.org"}},
	}))
}

// TestEgressDefaults_NoRedundantEntries pins the YAML source, not the computed
// union. The union builder deduplicates, so a host listed twice in the file is
// absorbed silently and TestEgressDefaults_LoadedFromYAML still passes. That
// makes redundant entries invisible in review: they accumulate, imply a host
// needs listing in several places, and make removing one occurrence look
// sufficient when it is not.
//
// Note the aliased ecosystems (npm_and_yarn/bun, pip/uv, maven/gradle,
// docker/docker_compose/devcontainers) legitimately resolve to identical
// slices, so duplicates are counted per distinct source list, not per key.
func TestEgressDefaults_NoRedundantEntries(t *testing.T) {
	withinList := func(t *testing.T, label string, hosts []string) {
		t.Helper()
		seen := make(map[string]struct{}, len(hosts))
		for _, host := range hosts {
			key := strings.ToLower(host)
			_, dup := seen[key]
			assert.Falsef(t, dup, "%s lists %q more than once", label, host)
			seen[key] = struct{}{}
		}
	}

	withinList(t, "github_infra_domains", githubInfraDomains)
	withinList(t, "shared_registry_domains", sharedRegistryDomains)

	// Distinct source lists only: aliased ecosystems share one backing slice.
	checked := make(map[string]bool)
	for _, ecosystem := range slices.Sorted(maps.Keys(ecosystemDefaultDomains)) {
		hosts := ecosystemDefaultDomains[ecosystem]
		fingerprint := strings.Join(hosts, "\n")
		if checked[fingerprint] {
			continue
		}
		checked[fingerprint] = true
		withinList(t, "ecosystem "+ecosystem, hosts)
	}

	// A host must not be repeated across the always-applied sections. Every one
	// of these is applied to every job, so a second listing is pure redundancy.
	// Ecosystem keys are compared against the shared/infra lists rather than
	// each other: two ecosystems legitimately naming the same public registry
	// is the documented reason the union exists.
	//
	// knownProvenanceCopies grandfathers hosts that are deliberately listed
	// twice because the ecosystem map doubles as documentation. Keep this set
	// small and justify every addition — it exists so that genuinely accidental
	// duplicates still fail.
	knownProvenanceCopies := map[string]string{
		// ghcr.io is GitHub infrastructure, but the container ecosystems list it
		// too so their entries read as a complete registry set.
		"ghcr.io": "documents that container ecosystems pull from GHCR",
	}

	always := map[string]string{}
	for _, host := range githubInfraDomains {
		always[strings.ToLower(host)] = "github_infra_domains"
	}
	for _, host := range sharedRegistryDomains {
		key := strings.ToLower(host)
		if where, ok := always[key]; ok {
			assert.Failf(t, "redundant entry",
				"%q is in both %s and shared_registry_domains", host, where)
		}
		always[key] = "shared_registry_domains"
	}
	for _, ecosystem := range slices.Sorted(maps.Keys(ecosystemDefaultDomains)) {
		for _, host := range ecosystemDefaultDomains[ecosystem] {
			key := strings.ToLower(host)
			if _, allowed := knownProvenanceCopies[key]; allowed {
				continue
			}
			if where, ok := always[key]; ok {
				assert.Failf(t, "redundant entry",
					"%q is in ecosystem %q and also in %s; the union applies both to every job",
					host, ecosystem, where)
			}
		}
	}

	// An exact host that an existing leading-dot or glob entry already covers is
	// dead weight: it can be deleted with no behaviour change, and its presence
	// falsely implies the namespace is not already open.
	var patterns []string
	for _, host := range allDefaultDomains() {
		if strings.HasPrefix(host, ".") || isGlobPattern(host) {
			patterns = append(patterns, host)
		}
	}
	for _, host := range allDefaultDomains() {
		if strings.HasPrefix(host, ".") || isGlobPattern(host) {
			continue
		}
		for _, pattern := range patterns {
			assert.Falsef(t, hostMatchesAllowlistEntry(host, pattern),
				"exact entry %q is already covered by %q; remove the redundant entry "+
					"(or, if %q must stay exact, narrow %q)", host, pattern, host, pattern)
		}
	}
}

// allDefaultDomains returns every host listed anywhere in the defaults file.
func allDefaultDomains() []string {
	hosts := slices.Clone(githubInfraDomains)
	hosts = append(hosts, sharedRegistryDomains...)
	for _, ecosystem := range slices.Sorted(maps.Keys(ecosystemDefaultDomains)) {
		hosts = append(hosts, ecosystemDefaultDomains[ecosystem]...)
	}
	return hosts
}

// Changelog and release-note hosts are reached by following package metadata
// (PyPI project_urls, POM <url>), not by resolving dependencies. They are
// allowed so pull requests keep their release notes; every entry is exact.
func TestEgressAllowlist_ChangelogHostsAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "")

	for _, allowed := range []string{
		"https://docs.pytest.org/en/stable/changelog.html",
		"https://docs.sqlalchemy.org/en/20/changelog/",
		"https://alembic.sqlalchemy.org/en/latest/changelog.html",
		"https://anyio.readthedocs.io/en/stable/versionhistory.html",
		"https://commons.apache.org/proper/commons-lang/changes.html",
		"https://developer.android.com/jetpack/androidx/releases/core",
		// Both ends of the two cross-host redirect chains.
		"https://docs.pydantic.dev/latest/changelog/",
		"https://pydantic.dev/docs/validation/latest/get-started/changelog/",
		"https://psycopg.org/docs/news.html",
		"https://www.psycopg.org/docs/news.html",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "changelog host allowed: "+allowed)
	}

	for _, blocked := range []string{
		// readthedocs.io subdomains are project-creatable, so allowing one
		// project must not expose the namespace or its apex.
		"https://evil.readthedocs.io/payload",
		"https://readthedocs.io/payload",
		"https://evil.anyio.readthedocs.io/payload",
		// Issue trackers, code browsers and vendor doc portals are deliberately
		// excluded: they carry no changelog Dependabot renders.
		"https://issues.apache.org/jira/browse/LANG",
		"https://cs.android.com/android/platform/superproject",
		"https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/home.html",
		// Exact entries must not widen to children or lookalike parents.
		"https://evil.docs.pytest.org/payload",
		"https://docs.pytest.org.attacker.com/payload",
		"https://pytest.org/payload",
		"https://evil.developer.android.com/payload",
		"https://android.com/payload",
		"https://apache.org/payload",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "must stay blocked: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

// Public vendor registries surfaced by the 75% enforce rollout. Each was
// verified to serve a real artifact anonymously with no cross-origin redirect.
func TestEgressAllowlist_PublicVendorRegistriesAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "")

	for _, allowed := range []string{
		"https://nexus.payara.fish/repository/payara-artifacts/fish/payara/api/payara-bom/maven-metadata.xml",
		"https://repository.mulesoft.org/nexus/content/repositories/public/org/mule/mule-core/maven-metadata.xml",
		"https://maven.repository.redhat.com/ga/org/jboss/jboss-parent/maven-metadata.xml",
		"https://artifacts.alfresco.com/nexus/content/repositories/public/org/alfresco/alfresco-core/maven-metadata.xml",
		"https://repo.grails.org/grails/core/org/grails/grails-core/maven-metadata.xml",
		"https://releases.aspose.com/java/repo/com/aspose/aspose-words/maven-metadata.xml",
		"https://api.opentofu.org/registry/docs/providers/hashicorp/aws/index.json",
		"https://wp-languages.github.io/packages.json",
		"https://pkg.go.dev/github.com/gorilla/mux",
		// SwiftPM binaryTarget downloads for the KARTE iOS SDK; the job fails in
		// the file parser without these, so no Swift PRs are opened at all.
		"https://sdk.karte.io/ios/swiftpm/Core-2.39.0/KarteCore-6aa9d244.xcframework.zip",
		"https://sdk.karte.io/ios/swiftpm/Utilities-3.16.0/KarteUtilities-6aa9d244.xcframework.zip",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "public vendor registry allowed: "+allowed)
	}

	for _, blocked := range []string{
		// github.io subdomains are user-creatable, so one Pages repository must
		// not expose the namespace or any sibling.
		"https://github.io/payload",
		"https://evil.github.io/payload",
		"https://evil.wp-languages.github.io/payload",
		// repo.magento.com returns 401: it needs a registries: credential, so
		// allowlisting the public hosts must not quietly cover it.
		"https://repo.magento.com/packages.json",
		// Multi-tenant hosts whose tenant lives in the path stay blocked, per
		// the dl.cloudsmith.io precedent.
		"https://packagecloud.io/org/repo/packages",
		"https://api.cloudsmith.io/v1/packages/org/repo/",
		// Exact entries must not widen to children or lookalike parents.
		"https://evil.nexus.payara.fish/payload",
		"https://payara.fish/payload",
		"https://evil.api.opentofu.org/payload",
		"https://opentofu.org/payload",
		"https://evil.pkg.go.dev/payload",
		"https://repo.grails.org.attacker.com/payload",
		// Every exact entry gets a child probe so a later widening to a
		// leading-dot suffix cannot pass silently.
		"https://evil.repo.grails.org/payload",
		"https://grails.org/payload",
		"https://evil.repository.mulesoft.org/payload",
		"https://evil.maven.repository.redhat.com/payload",
		"https://evil.artifacts.alfresco.com/payload",
		"https://evil.releases.aspose.com/payload",
		"https://evil.sdk.karte.io/payload",
		// karte.io serves a wildcard cert and resolves subdomains broadly, so
		// the SDK host must not drag the vendor's parent namespace in with it.
		"https://attacker.karte.io/payload",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "must stay blocked: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

// Second wave of changelog hosts, from the 75% rollout. Same rationale as
// TestEgressAllowlist_ChangelogHostsAllowed: metadata links, not resolution.
func TestEgressAllowlist_ChangelogHostsSecondWaveAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "")

	for _, allowed := range []string{
		"https://cryptography.io/en/latest/changelog/",
		"https://numpy.org/doc/stable/release.html",
		"https://docs.sentry.io/platforms/python/",
		"https://coverage.readthedocs.io/en/latest/changes.html",
		"https://reference.langchain.com/python/",
		"https://developer.nvidia.com/cuda-toolkit",
		"https://rubydoc.info/gems/rails",
		// cloud.google.com 301s to docs.cloud.google.com; both ends required.
		"https://cloud.google.com/python/docs/reference",
		"https://docs.cloud.google.com/python/docs/reference",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "changelog host allowed: "+allowed)
	}

	for _, blocked := range []string{
		// The Google Cloud web console is a sign-in flow, not a registry, and
		// allowing cloud.google.com must not reach it.
		"https://console.cloud.google.com/",
		// A project_urls community link, deliberately not allowlisted.
		"https://www.reddit.com/r/python/",
		// readthedocs.io stays exact-only: subdomains are project-creatable.
		"https://evil.readthedocs.io/payload",
		"https://evil.coverage.readthedocs.io/payload",
		// Exact entries must not widen.
		"https://evil.numpy.org/payload",
		"https://evil.cloud.google.com/payload",
		"https://google.com/payload",
		"https://cryptography.io.attacker.com/payload",
		"https://evil.cryptography.io/payload",
		"https://evil.docs.sentry.io/payload",
		"https://evil.reference.langchain.com/payload",
		"https://evil.developer.nvidia.com/payload",
		"https://evil.rubydoc.info/payload",
		"https://evil.docs.cloud.google.com/payload",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "must stay blocked: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

func TestEgressAllowlist_PublicRegistriesThirdWaveAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "")

	for _, allowed := range []string{
		"https://repo.opencollab.dev/maven-releases/org/geysermc/geyser/maven-metadata.xml",
		"https://maven.restlet.talend.com/org/restlet/jse/org.restlet/maven-metadata.xml",
		"https://maven.fpregistry.io/releases/io/fairyproject/maven-metadata.xml",
		"https://repo.essentialsx.net/releases/net/essentialsx/EssentialsX/maven-metadata.xml",
		"https://repo.dmulloy2.net/repository/public/com/comphenix/protocol/ProtocolLib/maven-metadata.xml",
		"https://api.xposed.info/api/de/robv/android/xposed/api/maven-metadata.xml",
		"https://packages.nuxeo.com/repository/maven-public/org/nuxeo/maven-metadata.xml",
		"https://maven.fullstory.com/com/fullstory/gradle-plugin/maven-metadata.xml",
		"https://maven.lokalise.com/com/lokalise/sdk/maven-metadata.xml",
		"https://repository.medallia.com/artifactory/public/com/medallia/maven-metadata.xml",
		"https://jogamp.org/deployment/maven/org/jogamp/gluegen/maven-metadata.xml",
		"https://jcenter.bintray.com/com/google/guava/guava/maven-metadata.xml",
		"https://salesforce-marketingcloud.github.io/MarketingCloudSDK-Android/maven-metadata.xml",
		"https://a8c-libs.s3.amazonaws.com/android/com/automattic/maven-metadata.xml",
		"https://nuxeo-devtools-nexus-central.s3.eu-west-1.amazonaws.com/storage/content/2026/10/01/22/02/82a2a8b2-184e-44a0-bc23-13e331e9fe10.bytes",
		"https://pkg.kzu.app/index.json",
		"https://archivist.terraform.io/v1/object/abc123",
		"https://storage.julialang.net/registries/23338594-aafe-5451-b93e-139f81909106",
		"https://julialang-storage-us-east-1.s3.us-east-1.amazonaws.com/package/abc",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "public registry allowed: "+allowed)
	}

	for _, blocked := range []string{
		// Path-style shared object storage must never be allowlisted: the apex
		// reaches every bucket, so only the exact virtual-hosted bucket is listed.
		"https://s3.amazonaws.com/attacker-bucket/payload",
		"https://s3.us-east-1.amazonaws.com/attacker-bucket/payload",
		"https://s3-us-west-2.amazonaws.com/attacker-bucket/payload",
		// Sibling Julia bucket names are unclaimed and therefore registrable, so
		// the region must never be globbed.
		"https://julialang-storage-eu-west-1.s3.eu-west-1.amazonaws.com/payload",
		"https://julialang-storage-evil.s3.us-east-1.amazonaws.com/payload",
		// Sibling Nuxeo bucket names are unregistered and therefore claimable,
		// so neither the bucket nor the region may be globbed.
		"https://nuxeo-devtools-nexus-evil.s3.eu-west-1.amazonaws.com/payload",
		"https://nuxeo-devtools-nexus-central.s3.us-east-1.amazonaws.com/payload",
		// github.io subdomains are user-creatable; one Pages repo must not
		// expose the namespace or any sibling.
		"https://evil.salesforce-marketingcloud.github.io/payload",
		// Hosts that return 401 need a registries: credential. Allowlisting the
		// public set must not quietly cover them.
		"https://mobile-sdks.forter.com/android/maven-metadata.xml",
		"https://nuget.devexpress.com/api/v3/index.json",
		// Commercial feeds tenanted by a license key in the path.
		"https://nuget.hangfire.io/pro/v3/index.json",
		"https://nuget.abp.io/key/v3/index.json",
		"https://registry.nes.herodevs.com/angular/core",
		"https://connect.advancedcustomfields.com/v1/plugins/download",
		// Application Insights telemetry ingestion, not a registry.
		"https://dc.services.visualstudio.com/v2/track",
		// Retired Bintray download host; only the JCenter redirector is listed.
		"https://dl.bintray.com/payload",
		// Every exact entry gets a child probe so a later widening to a
		// leading-dot suffix cannot pass silently.
		"https://evil.repo.opencollab.dev/payload",
		"https://evil.maven.restlet.talend.com/payload",
		"https://evil.maven.fpregistry.io/payload",
		"https://evil.repo.essentialsx.net/payload",
		"https://evil.repo.dmulloy2.net/payload",
		"https://evil.api.xposed.info/payload",
		"https://evil.packages.nuxeo.com/payload",
		"https://evil.maven.fullstory.com/payload",
		"https://evil.maven.lokalise.com/payload",
		"https://evil.repository.medallia.com/payload",
		"https://evil.jogamp.org/payload",
		"https://evil.jcenter.bintray.com/payload",
		"https://evil.pkg.kzu.app/payload",
		"https://evil.archivist.terraform.io/payload",
		"https://evil.storage.julialang.net/payload",
		// The exact S3 entries need child probes of their own: the sibling
		// and apex probes above catch a glob or a path-style widening, but only
		// these catch the entry being changed to a leading-dot suffix.
		"https://evil.a8c-libs.s3.amazonaws.com/payload",
		"https://evil.julialang-storage-us-east-1.s3.us-east-1.amazonaws.com/payload",
		"https://evil.nuxeo-devtools-nexus-central.s3.eu-west-1.amazonaws.com/payload",
		// Lookalike parents and suffix-appending attacker domains.
		"https://bintray.com/payload",
		"https://talend.com/payload",
		"https://nuxeo.com/payload",
		"https://fullstory.com/payload",
		"https://lokalise.com/payload",
		"https://medallia.com/payload",
		"https://essentialsx.net/payload",
		"https://xposed.info/payload",
		"https://julialang.net/payload",
		"https://archivist.terraform.io.attacker.com/payload",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "must stay blocked: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

func TestEgressAllowlist_ChangelogHostsThirdWaveAllowed(t *testing.T) {
	h := newEgressHandler(false, true, "")

	for _, allowed := range []string{
		"https://click.palletsprojects.com/en/stable/changes/",
		"https://pytest-mock.readthedocs.io/en/latest/changelog.html",
		"https://redis.readthedocs.io/en/stable/",
		"https://logging.apache.org/log4j/2.x/release-notes.html",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "changelog host allowed: "+allowed)
	}

	for _, blocked := range []string{
		// readthedocs.io subdomains are project-creatable, so each entry stays
		// exact and the namespace itself must never resolve.
		"https://readthedocs.io/payload",
		"https://evil.readthedocs.io/payload",
		"https://evil.pytest-mock.readthedocs.io/payload",
		"https://evil.redis.readthedocs.io/payload",
		// Child probes guard against a later widening to a leading-dot suffix.
		"https://evil.click.palletsprojects.com/payload",
		"https://evil.logging.apache.org/payload",
		// Lookalike parents and suffix-appending attacker domains.
		"https://palletsprojects.com/payload",
		"https://logging.apache.org.attacker.com/payload",
		// Issue trackers and code browsers carry no renderable changelog.
		"https://issues.apache.org/jira/browse/LOG4J2-1",
		"https://cs.android.com/android/platform/superproject",
		"https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/home.html",
		// Chat and link-aggregator hosts reached via project_urls metadata.
		"https://gitter.im/org/room",
		"https://www.reddit.com/r/python/",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "must stay blocked: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}

// TestEgressAllowlist_AnonymousCredentialAllowlistsHost pins the behaviour the
// org-level Anonymous registry option depends on: a credential carrying only a
// registry location, with no secret of any kind, must still contribute its host
// to the per-job allowlist. This is why an anonymous registry has to appear in
// the job credentials at all, and therefore why the handlers must skip
// authenticating it rather than the config omitting it.
func TestEgressAllowlist_AnonymousCredentialAllowlistsHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		cred config.Credential
		host string
	}{
		{
			name: "npm_registry via registry",
			cred: config.Credential{"type": "npm_registry", "registry": "nexus.example.net/repository/npm-all"},
			host: "nexus.example.net",
		},
		{
			name: "docker_registry via registry",
			cred: config.Credential{"type": "docker_registry", "registry": "docker.example.net"},
			host: "docker.example.net",
		},
		{
			name: "python_index via index-url",
			cred: config.Credential{"type": "python_index", "index-url": "https://pypi.example.net/simple"},
			host: "pypi.example.net",
		},
		{
			name: "maven_repository via url",
			cred: config.Credential{"type": "maven_repository", "url": "https://maven.example.net/releases"},
			host: "maven.example.net",
		},
		{
			name: "nuget_feed via url",
			cred: config.Credential{"type": "nuget_feed", "url": "https://nuget.example.net/v3/index.json"},
			host: "nuget.example.net",
		},
		{
			name: "colon token is still anonymous",
			cred: config.Credential{"type": "npm_registry", "registry": "colon.example.net", "token": ":"},
			host: "colon.example.net",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newEgressHandlerWithCreds(config.Credentials{tc.cred})
			assert.Nil(t, egressResult(t, h, "https://"+tc.host+"/some/path"),
				"anonymous credential must allowlist its host: "+tc.host)
		})
	}
}

// TestEgressAllowlist_AnonymousCredentialDoesNotWidenBeyondExactHost holds the
// dynamic-host exact-match invariant for credential-free entries specifically.
// Dynamic hosts are matched with AreHostnamesEqual only, so declaring an
// anonymous registry must authorize that one host and nothing beneath or beside
// it. These probes fail the moment dynamic matching is relaxed to a suffix.
func TestEgressAllowlist_AnonymousCredentialDoesNotWidenBeyondExactHost(t *testing.T) {
	h := newEgressHandlerWithCreds(config.Credentials{
		config.Credential{"type": "npm_registry", "registry": "nexus.example.net/repository/npm-all"},
	})

	for _, blocked := range []string{
		// Child probe: fails if the dynamic entry becomes a leading-dot suffix.
		"https://evil.nexus.example.net/repository/npm-all",
		// Sibling probe: fails if the entry is widened to its parent namespace.
		"https://attacker.example.net/repository/npm-all",
		// Suffix-appending lookalike.
		"https://nexus.example.net.attacker.com/repository/npm-all",
	} {
		resp := egressResult(t, h, blocked)
		if assert.NotNil(t, resp, "must stay blocked: "+blocked) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}
