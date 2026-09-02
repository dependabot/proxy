package handlers

// githubInfraDomains are the GitHub and Dependabot infrastructure domains that
// are always allowed. Subdomains are matched too, so github.com also covers
// api.github.com / codeload.github.com, githubusercontent.com covers
// objects/raw.githubusercontent.com, and ghe.com covers api.<tenant>.ghe.com.
var githubInfraDomains = []string{
	"github.com",
	"githubusercontent.com",
	"githubapp.com",
	"ghe.com",
	"ghcr.io",
}

// ecosystemDefaultDomains maps a Dependabot package manager (the PACKAGE_MANAGER
// env value) to the public registry and CDN domains it needs. Subdomains of
// each entry are allowed by the suffix matcher, so listing the registrable
// domain (e.g. "npmjs.org") also covers "registry.npmjs.org".
var ecosystemDefaultDomains = map[string][]string{
	"npm_and_yarn":   {"npmjs.org", "yarnpkg.com"},
	"bun":            {"npmjs.org", "yarnpkg.com"},
	"pip":            {"pypi.org", "pythonhosted.org"},
	"uv":             {"pypi.org", "pythonhosted.org"},
	"bundler":        {"rubygems.org"},
	"maven":          {"maven.apache.org", "maven.org", "gradle.org", "dl.google.com"},
	"gradle":         {"maven.apache.org", "maven.org", "gradle.org", "dl.google.com"},
	"cargo":          {"crates.io"},
	"composer":       {"packagist.org"},
	"go_modules":     {"proxy.golang.org", "sum.golang.org", "storage.googleapis.com"},
	"docker":         {"docker.io", "docker.com", "gcr.io", "public.ecr.aws", "mcr.microsoft.com", "quay.io"},
	"docker_compose": {"docker.io", "docker.com", "gcr.io", "public.ecr.aws", "mcr.microsoft.com", "quay.io"},
	"nuget":          {"nuget.org"},
	"dotnet_sdk":     {"nuget.org"},
	"hex":            {"hex.pm"},
	"pub":            {"pub.dev", "pub.dartlang.org", "storage.googleapis.com"},
	"terraform":      {"registry.terraform.io", "releases.hashicorp.com"},
}
