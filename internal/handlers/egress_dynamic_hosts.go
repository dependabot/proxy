package handlers

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/dependabot/proxy/internal/config"
)

// ecrHostPattern matches the canonical private ECR registry host,
// "<account-id>.dkr.ecr.<region>.amazonaws.com", capturing the region.
//
// The region is interpolated into an allowlist entry, so the account is anchored
// to 12 digits and the region to a single dot-free label: a crafted credential
// must not be able to widen the derived host. A path.Match glob cannot serve
// here — it has no capture group, and its "*" spans dots.
var ecrHostPattern = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$`)

// gemfuryStorageHost is the single Gemfury-owned S3 bucket that every Gemfury
// registry (pypi.fury.io, npm.fury.io, ...) 302-redirects package downloads to
// via short-lived pre-signed URLs.
const gemfuryStorageHost = "gemfury.s3-accelerate.dualstack.amazonaws.com"

// registryRedirectHosts returns storage backends that a configured registry
// redirects to on download but that appear in no credential field.
//
// Private ECR 307-redirects layer downloads to a per-region, AWS-owned S3
// bucket. It is derived per job rather than globbed into the static defaults
// because "prod-<anything>-starport-layer-bucket" is a claimable S3 name, so a
// glob would hand every job an attacker-registrable destination.
//
// Gemfury redirects to one fixed bucket shared by all Gemfury accounts, with
// the account in the URL path. It is derived per job rather than added to the
// static defaults because allowing a shared multi-tenant host there would open
// every tenant's content to every job. The derived host is a constant, so a
// crafted credential cannot widen it.
func registryRedirectHosts(credHosts []string) []string {
	var hosts []string
	for _, h := range credHosts {
		if m := ecrHostPattern.FindStringSubmatch(h); m != nil {
			region := m[1]
			hosts = append(hosts, fmt.Sprintf("prod-%s-starport-layer-bucket.s3.%s.amazonaws.com", region, region))
		}
		if strings.HasSuffix(h, ".fury.io") {
			hosts = append(hosts, gemfuryStorageHost)
		}
	}
	return hosts
}

// credentialHostKeys are the credential fields that carry a registry host or
// URL. The host of each is added to the per-job allowlist so that the private
// registries a job is configured to use are never treated as exfiltration.
var credentialHostKeys = []string{
	"host",
	"url",
	"index-url",
	"registry",
	"api-host",
	"repo",
	"endpoint",
	"replaces-base",
}

// hostFromValue extracts a lower-cased hostname from a credential value that may
// be a full URL ("https://host/path"), a bare host ("host"), or a host:port.
// It returns "" when no host can be determined.
func hostFromValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// url.Parse only populates Hostname() when an authority is present, so add
	// the "//" marker for scheme-less values (bare host, host:port, host/path).
	if !strings.Contains(v, "://") {
		v = "//" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// credentialHosts returns the hosts a job is explicitly configured to reach:
// the host of every URL-bearing credential field. These are inherently trusted
// for this job.
func credentialHosts(creds config.Credentials) []string {
	var hosts []string
	for _, c := range creds {
		for _, key := range credentialHostKeys {
			if h := hostFromValue(c.GetString(key)); h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	return hosts
}

// oidcExchangeHosts returns the identity-provider token-exchange endpoints the
// proxy itself contacts to mint a token when a credential is OIDC-configured.
// The eventual target registry host is already covered by credentialHosts (via
// url/api-host/registry), so only the provider auth endpoints are added here.
// Detection mirrors the identifying keys used by oidc.CreateOIDCCredential.
func oidcExchangeHosts(creds config.Credentials) []string {
	var hosts []string
	for _, c := range creds {
		// Azure AD.
		if c.GetString("tenant-id") != "" && c.GetString("client-id") != "" {
			hosts = append(hosts, "login.microsoftonline.com")
		}
		// AWS STS (CodeArtifact target host comes from the credential url).
		if c.GetString("aws-region") != "" && c.GetString("role-name") != "" {
			hosts = append(hosts, "sts.amazonaws.com")
		}
		// GCP Workload Identity Federation.
		if c.GetString("workload-identity-provider") != "" {
			hosts = append(hosts,
				"sts.googleapis.com",
				"iamcredentials.googleapis.com",
				"www.googleapis.com",
			)
		}
		// Cloudsmith.
		if c.GetString("service-slug") != "" && c.GetString("organization") != "" {
			apiHost := c.GetString("api-host")
			if apiHost == "" {
				apiHost = "api.cloudsmith.io"
			}
			hosts = append(hosts, strings.ToLower(apiHost))
		}
		// JFrog exchanges the token against the JFrog server itself, whose host
		// is already captured from the credential url by credentialHosts.
	}
	return hosts
}

// dynamicHosts returns the deduplicated per-job hosts derived from the job's
// credentials: configured registries, OIDC token-exchange endpoints, and the
// storage backends those registries redirect to for content downloads.
func dynamicHosts(creds config.Credentials) []string {
	credHosts := credentialHosts(creds)

	all := make([]string, 0, len(credHosts))
	all = append(all, credHosts...)
	all = append(all, oidcExchangeHosts(creds)...)
	all = append(all, registryRedirectHosts(credHosts)...)

	seen := make(map[string]struct{})
	var out []string
	for _, h := range all {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
