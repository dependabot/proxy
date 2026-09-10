package handlers

import (
	_ "embed"
	"fmt"
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
	EcosystemDefaultDomains map[string][]string `yaml:"ecosystem_default_domains"`
}

var (
	// githubInfraDomains are the GitHub/Dependabot infrastructure domains that
	// are always allowed, regardless of ecosystem.
	githubInfraDomains []string

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
}
