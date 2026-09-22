package handlers

import (
	_ "embed"
	"fmt"
	"path"
	"slices"

	"gopkg.in/yaml.v3"
)

// egressDefaultsYAML holds the allowlist defaults. It is the single source of
// truth for the GitHub infrastructure domains and per-ecosystem registry hosts;
// see the file itself for the matching convention and provenance notes.
//
//go:embed egress_allowlist_defaults.yaml
var egressDefaultsYAML []byte

// egressDefaults is the parsed representation of egress_allowlist_defaults.yaml.
type egressDefaults struct {
	GithubInfraDomains      []string            `yaml:"github_infra_domains"`
	SharedRegistryDomains   []string            `yaml:"shared_registry_domains"`
	EcosystemDefaultDomains map[string][]string `yaml:"ecosystem_default_domains"`
}

var (
	// githubInfraDomains are the GitHub/Dependabot infrastructure domains that
	// are always allowed, regardless of ecosystem.
	githubInfraDomains []string

	// sharedRegistryDomains are third-party registry/artifact providers that
	// serve many ecosystems at once (e.g. JFrog, CodeArtifact, Azure Artifacts).
	// They are applied to every job, like allEcosystemDomains, but are kept in a
	// separate list because they do not belong to any single ecosystem.
	sharedRegistryDomains []string

	// ecosystemDefaultDomains maps each Dependabot ecosystem to the public
	// registry/CDN hosts it needs. Retained for provenance/documentation; the
	// handler applies the union (allEcosystemDomains), not a per-key lookup.
	ecosystemDefaultDomains map[string][]string

	// allEcosystemDomains is the deduplicated union of every ecosystem's
	// defaults, applied to all jobs. We intentionally do not partition by
	// PACKAGE_MANAGER: launchers do not reliably set it, and multi-ecosystem
	// jobs need several ecosystems at once. All entries are trusted public
	// registries, so the loss of cross-ecosystem isolation is negligible versus
	// the exfiltration protection (unknown hosts are still blocked).
	allEcosystemDomains []string
)

func init() {
	var defaults egressDefaults
	if err := yaml.Unmarshal(egressDefaultsYAML, &defaults); err != nil {
		panic(fmt.Sprintf("parsing egress_allowlist_defaults.yaml: %v", err))
	}

	githubInfraDomains = defaults.GithubInfraDomains
	sharedRegistryDomains = defaults.SharedRegistryDomains
	ecosystemDefaultDomains = defaults.EcosystemDefaultDomains

	seen := make(map[string]struct{})
	for _, hosts := range ecosystemDefaultDomains {
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			allEcosystemDomains = append(allEcosystemDomains, host)
		}
	}
	slices.Sort(allEcosystemDomains)

	// Fail fast on malformed glob patterns in the embedded defaults rather than
	// silently never-matching them at request time.
	validateGlobDefaults(githubInfraDomains)
	validateGlobDefaults(sharedRegistryDomains)
	validateGlobDefaults(allEcosystemDomains)
}

// validateGlobDefaults panics if any glob entry is not a valid path.Match
// pattern. This runs from init (package initialization), so a malformed glob
// fails at program startup — and in `go test` — rather than at `go build` time
// (init is not executed by the compiler). Failing here beats silently
// never-matching (and thus dropping a host we meant to allow) at request time.
func validateGlobDefaults(entries []string) {
	for _, entry := range entries {
		if !isGlobPattern(entry) {
			continue
		}
		if err := validateGlobPattern(entry); err != nil {
			panic(fmt.Sprintf("invalid glob in egress_allowlist_defaults.yaml: %q: %v", entry, err))
		}
	}
}

// validateGlobPattern reports whether pattern is a syntactically valid
// path.Match pattern. path.Match scans the remainder of the pattern for syntax
// errors even after an earlier segment fails to match, so probing with any
// sample (here the empty string) surfaces ErrBadPattern for malformed patterns
// such as "foo*bar[" (an unterminated character class). We validate against the
// exact matcher used at request time, so the two can never disagree.
func validateGlobPattern(pattern string) error {
	_, err := path.Match(pattern, "")
	return err
}
