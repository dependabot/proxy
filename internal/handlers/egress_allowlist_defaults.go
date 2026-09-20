package handlers

import (
	_ "embed"
	"fmt"
	"path"
	"slices"
	"unicode/utf8"

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
// pattern, so a malformed glob fails the build instead of silently never
// matching (and thus dropping a host we meant to allow) at request time.
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
// path.Match pattern. path.Match only surfaces ErrBadPattern once matching
// actually reaches the malformed token, so probing with a single sample string
// cannot exercise every branch — e.g. path.Match("foo*bar[", "example.com")
// returns (false, nil) after the literal "foo" fails, never inspecting the
// unterminated class. This validates the pattern's structure directly, mirroring
// path.Match's grammar for escapes and character classes.
func validateGlobPattern(pattern string) error {
	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '\\':
			// The proxy does not run on Windows (where path.Match treats '\' as
			// a literal); elsewhere '\' escapes the next byte, so a trailing one
			// is malformed.
			if i+1 >= len(pattern) {
				return path.ErrBadPattern
			}
			i += 2
		case '[':
			n, err := scanCharClass(pattern[i:])
			if err != nil {
				return err
			}
			i += n
		default:
			i++
		}
	}
	return nil
}

// scanCharClass validates a leading "[...]" character class and returns its
// length in bytes. It follows path.Match's grammar: an optional leading '^',
// then one or more range elements, terminated by ']'. Each element is a single
// (optionally '\'-escaped) rune, optionally followed by '-' and a second rune.
func scanCharClass(s string) (int, error) {
	i := 1 // skip the opening '['
	if i < len(s) && s[i] == '^' {
		i++
	}
	for elems := 0; ; elems++ {
		if i < len(s) && s[i] == ']' && elems > 0 {
			return i + 1, nil
		}
		n, err := scanClassRune(s[i:])
		if err != nil {
			return 0, err
		}
		i += n
		if i < len(s) && s[i] == '-' {
			n, err := scanClassRune(s[i+1:])
			if err != nil {
				return 0, err
			}
			i += 1 + n
		}
	}
}

// scanClassRune consumes one (optionally escaped) rune inside a character class,
// mirroring path.Match's getEsc: '-' and ']' are not valid element starts, and
// the class may not end at this rune (a closing ']' must still follow).
func scanClassRune(s string) (int, error) {
	if len(s) == 0 || s[0] == '-' || s[0] == ']' {
		return 0, path.ErrBadPattern
	}
	i := 0
	if s[0] == '\\' {
		i++
		if i >= len(s) {
			return 0, path.ErrBadPattern
		}
	}
	r, w := utf8.DecodeRuneInString(s[i:])
	if r == utf8.RuneError && w == 1 {
		return 0, path.ErrBadPattern
	}
	i += w
	if i >= len(s) {
		return 0, path.ErrBadPattern
	}
	return i, nil
}
