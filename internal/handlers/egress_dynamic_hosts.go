package handlers

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
)

// ecrHostPattern matches the canonical private ECR registry host,
// "<account-id>.dkr.ecr.<region>.amazonaws.com", capturing the region.
//
// The region is interpolated into an allowlist entry, so the account is anchored
// to 12 digits and the region to a single dot-free label: a crafted credential
// must not be able to widen the derived host. A path.Match glob cannot serve
// here — it has no capture group, and its "*" spans dots.
var ecrHostPattern = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$`)

// registryRedirectDerivation maps a credential host to the fixed storage hosts
// that registry redirects downloads to. The derived hosts are constants, so a
// crafted credential cannot widen the destination.
type registryRedirectDerivation struct {
	// CredentialHost matches exactly, or, with a leading dot, any subdomain of
	// that domain but not the apex.
	CredentialHost string   `yaml:"credential_host"`
	Derived        []string `yaml:"derived"`
}

// registryRedirectDerivations is loaded from the registry_redirect_derivations
// section of egress_allowlist_defaults.yaml, which documents the rules for
// adding one. Derivations whose target embeds a credential-derived value (ECR)
// stay in registryRedirectHosts below.
var registryRedirectDerivations []registryRedirectDerivation

// registryRedirectHosts returns storage backends that a configured registry
// redirects to on download but that appear in no credential field.
//
// Private ECR is the exception to registryRedirectDerivations: its layer bucket
// embeds the region, so the host is interpolated from the job's own credential
// rather than globbed into the static defaults, where
// "prod-<anything>-starport-layer-bucket" would be an attacker-registrable name.
func registryRedirectHosts(credHosts []string) []string {
	var hosts []string
	for _, h := range credHosts {
		// hostFromValue lower-cases; drop the absolute-DNS trailing dot too.
		h = strings.TrimSuffix(h, ".")

		for _, derivation := range registryRedirectDerivations {
			if derivation.matches(h) {
				hosts = append(hosts, derivation.Derived...)
			}
		}

		if m := ecrHostPattern.FindStringSubmatch(h); m != nil {
			region := m[1]
			hosts = append(hosts, fmt.Sprintf("prod-%s-starport-layer-bucket.s3.%s.amazonaws.com", region, region))
		}
	}
	return hosts
}

func (d registryRedirectDerivation) matches(host string) bool {
	if strings.HasPrefix(d.CredentialHost, ".") {
		return strings.HasSuffix(host, d.CredentialHost)
	}
	return helpers.AreHostnamesEqual(host, d.CredentialHost)
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
