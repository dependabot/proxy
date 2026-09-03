package handlers

// Allowlist entries are matched by EgressAllowlistHandler with this convention:
// a leading dot (".github.com") matches that domain and any subdomain, while an
// entry without a leading dot ("storage.googleapis.com") matches only that exact
// host. Prefer exact hosts. Use the leading-dot form only for domains whose
// subdomains are entirely provider-controlled and never user-creatable, so that
// user-controlled subdomains — e.g. object-storage buckets reachable as
// <bucket>.storage.googleapis.com — cannot be abused as an exfiltration channel.

// githubInfraDomains are the GitHub and Dependabot infrastructure domains that
// are always allowed. Their subdomains are entirely GitHub-controlled (api.,
// codeload., objects./raw.githubusercontent.com, api.<tenant>.ghe.com), so the
// leading-dot suffix form is safe here.
var githubInfraDomains = []string{
	".github.com",
	".githubusercontent.com",
	".githubapp.com",
	".ghe.com",
	"ghcr.io",
}

// ecosystemDefaultDomains maps a Dependabot package manager (the PACKAGE_MANAGER
// env value, which is Dependabot's internal name such as "go_modules", not the
// dependabot.yml value "gomod") to the public registry and CDN hosts it needs.
// Entries are exact hosts unless a leading dot is present. Object-storage hosts
// (storage.googleapis.com) are intentionally exact so user-created buckets under
// them are not allowlisted.
//
// Ecosystems that resolve only over git or from user-configured registries have
// no entry on purpose: github_actions, git_submodules, swift, vcpkg, nix,
// pre_commit, devcontainers (all covered by githubInfraDomains, git, or the
// job's own credentials) and helm (basic-auth registries supplied per job).
var ecosystemDefaultDomains = map[string][]string{
	"npm_and_yarn":   {"registry.npmjs.org", "registry.yarnpkg.com"},
	"bun":            {"registry.npmjs.org", "registry.yarnpkg.com"},
	"pip":            {"pypi.org", "files.pythonhosted.org"},
	"uv":             {"pypi.org", "files.pythonhosted.org"},
	"bundler":        {"rubygems.org", "index.rubygems.org"},
	"maven":          {"repo.maven.apache.org", "repo1.maven.org", "plugins.gradle.org", "dl.google.com"},
	"gradle":         {"repo.maven.apache.org", "repo1.maven.org", "plugins.gradle.org", "dl.google.com"},
	"sbt":            {"repo1.maven.org", "repo.maven.apache.org", "repo.scala-sbt.org"},
	"cargo":          {"crates.io", "static.crates.io", "index.crates.io"},
	"composer":       {"repo.packagist.org", "packagist.org"},
	"go_modules":     {"proxy.golang.org", "sum.golang.org", "storage.googleapis.com"},
	"docker":         {"registry-1.docker.io", "auth.docker.io", "index.docker.io", "production.cloudflare.docker.com", "ghcr.io", "mcr.microsoft.com", "quay.io", "public.ecr.aws", ".gcr.io", ".pkg.dev"},
	"docker_compose": {"registry-1.docker.io", "auth.docker.io", "index.docker.io", "production.cloudflare.docker.com", "ghcr.io", "mcr.microsoft.com", "quay.io", "public.ecr.aws", ".gcr.io", ".pkg.dev"},
	"nuget":          {"api.nuget.org"},
	"dotnet_sdk":     {"api.nuget.org"},
	"hex":            {"repo.hex.pm", "hex.pm"},
	"pub":            {"pub.dev", "pub.dartlang.org", "storage.googleapis.com"},
	"terraform":      {"registry.terraform.io", "releases.hashicorp.com"},
	"opentofu":       {"registry.opentofu.org", "releases.hashicorp.com"},
	"elm":            {"package.elm-lang.org"},
	"deno":           {"jsr.io", "deno.land", "registry.npmjs.org"},
	"bazel":          {"bcr.bazel.build"},
	"julia":          {"pkg.julialang.org"},
	"rust_toolchain": {"static.rust-lang.org"},
}


