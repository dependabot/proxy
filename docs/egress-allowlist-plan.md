# Plan: Egress Allowlist in the Dependabot Proxy

## Goal

Add domain-based egress control to the proxy: build an allowlist of known non-hostile domains per update job and drop requests to anything else with a **403**. This prevents source-code exfiltration to `evil.com` even when an attacker abuses a user-provided registry token (e.g. Artifactory / Nexus), which the original Method-header idea could not address.

**Approach:** hybrid list (static ecosystem defaults + backend-config extras + auto-derived from credentials), shipped **observe (log-only) first**, **fail-open** when no allowlist is configured, then enforcement flipped **per-ecosystem starting with those that execute arbitrary code**.


## Decisions

- **List source = Hybrid:** static per-ecosystem defaults in the proxy + config-provided extras (backend) + auto-derived from credential hosts.
- **Two independent feature flags:**
  - **`observe`** (logging mode) — when set, non-allowlisted requests are logged but still allowed. This is the safe rollout / discovery mode.
  - **`enforce`** (blocking mode) — when set, non-allowlisted requests are dropped with **403**.
  - The flags are independent: `observe` gathers data without impact; `enforce` blocks. Enabling `enforce` is the switch that actually protects the job; `observe` can stay on alongside it for continued visibility.
- **Fail mode = Fail-open** when neither flag is set (opt-in, backward compatible for existing jobs / GHES).
- **Blocked response = 403 Forbidden**, consistent with the existing 403 used for blocked IPs (`blockMetadataAPIHosts`).

## Enforcement Point

A new `OnRequest().DoFunc` handler registered in `proxy.go` **after** `blockMetadataAPIHosts` and **before** the credential-injecting handlers, so drops happen before any auth is added. Works for HTTP and MITM'd HTTPS because goproxy's `AlwaysMitm` exposes the real `req.URL.Host` to `DoFunc`. Matching uses `helpers.GetHost` + `helpers.AreHostnamesEqual` plus a subdomain-suffix matcher.

## Steps

### Phase 1 — Config plumbing

1. Add an `EgressAllowlist` struct to `internal/config/config.go` (`observe bool`, `enforce bool`, `domains []string`) and an `egress_allowlist` field on `Config`. Absent / both flags false ⇒ allow-all. (If the backend surfaces these as experiments instead, gate on `proxy_egress_allowlist_observe` / `proxy_egress_allowlist_enforce` via the `experiments` map, mirroring `proxy_read_only_git_credentials`.)

### Phase 2 — Handler (depends on 1)

2. New `internal/handlers/egress_allowlist_defaults.go` — a `map[packageManager][]string` of known public registry + CDN domains (suffix entries like `.npmjs.org`), mirroring dependabot-core defaults.
3. New `internal/handlers/egress_allowlist.go` — `NewEgressAllowlistHandler(cfg, env)` composes the allowed set from:
   - GitHub/API infra defaults + `DEPENDABOT_API_URL` host
   - per-ecosystem defaults keyed by `env.PackageManager`
   - each `cred.Host()` from `cfg.Credentials`, **plus OIDC-authenticated registry hosts derived from OIDC params / `oidcRegistry` registered URLs** (see OIDC Considerations)
   - `cfg.EgressAllowlist.Domains`

   `HandleRequest` allows the request when the host matches, or when neither flag is set. On a non-allowlisted host it evaluates the two flags independently:
   - if `observe` ⇒ log the miss via `logging.RequestLogf("* egress not allowlisted ...")`;
   - if `enforce` ⇒ return `goproxy.NewResponse(req, ..., http.StatusForbidden, "")` (**403**).

   With both set, log **and** block. With only `observe`, log and allow.

### Phase 3 — Wiring (depends on 2, 3)

4. Register the handler in `proxy.go` immediately after `blockMetadataAPIHosts` and before the credential handlers.

### Phase 4 — Tests (parallel with 3–4)

5. Unit, config, and integration tests (see Verification).

## Per-Ecosystem Default Domains

Suffix entries (leading `.`) match subdomains. Source of truth: mirror dependabot-core's default registries per ecosystem.

| Ecosystem            | Domains |
|----------------------|---------|
| npm / yarn / pnpm    | `registry.npmjs.org`, `registry.yarnpkg.com`, `.npmjs.org` |
| pip / python         | `pypi.org`, `files.pythonhosted.org`, `.pythonhosted.org` |
| bundler              | `rubygems.org`, `index.rubygems.org`, `.rubygems.org` |
| maven / gradle       | `repo.maven.apache.org`, `repo1.maven.org`, `plugins.gradle.org`, `dl.google.com`, `.maven.org` |
| cargo                | `crates.io`, `static.crates.io`, `index.crates.io`, `.crates.io` |
| composer             | `repo.packagist.org`, `packagist.org`, `.packagist.org` |
| go_modules           | `proxy.golang.org`, `sum.golang.org`, `storage.googleapis.com` |
| docker               | `registry-1.docker.io`, `auth.docker.io`, `index.docker.io`, `production.cloudflare.docker.com`, `.docker.io`, `ghcr.io`, `.gcr.io`, `public.ecr.aws`, `mcr.microsoft.com`, `quay.io` |
| nuget                | `api.nuget.org`, `.nuget.org` |
| hex / mix            | `repo.hex.pm`, `hex.pm`, `.hex.pm` |
| pub                  | `pub.dev`, `pub.dartlang.org`, `storage.googleapis.com` |
| terraform            | `registry.terraform.io`, `releases.hashicorp.com` |

**Always-allowed infra:** `github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `raw.githubusercontent.com`, `uploads.github.com`, `api.<tenant>.ghe.com`, `codeload.<tenant>.ghe.com`, and the `DEPENDABOT_API_URL` host.

## OIDC Considerations

OIDC involves two distinct traffic flows, and only one of them passes through the allowlist handler.

### 1. Token-exchange handshake — bypasses the allowlist

OIDC token-exchange calls are made by the **proxy process itself** via the `oidcClient` (`&http.Client{Transport: transport}`) created in `proxy.go`, using `client.Do(req)` directly (see `internal/oidc/actions_oidc.go`). They are **not** job traffic submitted to the goproxy server, so they never run through the `OnRequest().DoFunc` chain where the allowlist lives. They are still IP-guarded by the `safeDialer` in `internal/dialer/dialer.go`, but the domain allowlist neither sees nor blocks them — so these hosts do **not** need an allowlist entry for OIDC to work.

Token-exchange endpoints (listed for reference / defense-in-depth defaults only):

| Provider | Token-exchange host(s) | Source |
|----------|------------------------|--------|
| GitHub Actions (ID token) | host of `ACTIONS_ID_TOKEN_REQUEST_URL` (env) | `actions_oidc.go` `GetToken` |
| Azure | `login.microsoftonline.com` | `actions_oidc.go` |
| JFrog | `<JFrogURL host>` (`/access/api/v1/oidc/token`) | `actions_oidc.go` |
| AWS | `sts.amazonaws.com`, `codeartifact.<region>.amazonaws.com` | `actions_oidc.go` |
| Cloudsmith | `api.cloudsmith.io` (or configured `api-host`) | `actions_oidc.go` |
| GCP | `sts.googleapis.com`, `iamcredentials.googleapis.com` | `actions_oidc.go` |

### 2. Job request to the OIDC-authenticated registry — DOES pass through the allowlist

After the exchange, the proxy injects the fetched token onto the **update job's** request to the actual package registry. That request is proxied job traffic and must be allowlisted. Most registry hosts are covered by `cred.Host()`, but several OIDC registry endpoints are **dynamically constructed** and not present as the credential's `host`/`url`, so they would be dropped:

- **AWS CodeArtifact** — endpoint derived from `domain`, `domain-owner`, `region` (e.g. `<domain>-<owner>.d.codeartifact.<region>.amazonaws.com`), not a literal `url`.
- **GCP Artifact Registry** — endpoints like `<region>-<repo>.pkg.dev` constructed from OIDC params.
- **Azure DevOps artifacts** — `pkgs.dev.azure.com` feeds where the registered URL may differ from `cred.Host()`.

The allowlist builder should derive these from the **OIDC parameters** (`AWSOIDCParameters`, `GCPOIDCParameters`, etc. in `internal/oidc/oidc_credential.go`) and/or the URLs already tracked via `oidcRegistry.RegisterURL(...)` (see `internal/handlers/python_index.go`), rather than reconstructing hosts by hand. Registries that redirect to CDN/blob download hosts need the same download-prefix learning described below.

## How to Identify the Non-Hostile Domains

1. Seed static defaults from dependabot-core's known registries **and their CDNs** — the fragile part is registries redirecting to CDNs (`pypi.org` → `files.pythonhosted.org`, `crates.io` → `static.crates.io`, npm/gems → Fastly). Extend the existing PyPI download-prefix learning in `internal/handlers/python_index_download_prefixes.go` as the model for private-index CDN discovery.
2. Auto-include configured registries (from credentials, including OIDC-derived registry hosts) + GitHub/API infra.
3. Ship with **`observe`** on and `enforce` off; aggregate `"* egress not allowlisted"` lines in Splunk across real jobs; fold legitimate misses into the defaults — the same operational loop as the existing `add-missing-regex-to-allowlist` runbook.
4. Flip **`enforce`** per-ecosystem, **executing-code ecosystems first** (bundler, npm, pip/python, composer, cargo, mix/hex, gradle/maven-with-plugins), then non-executing ecosystems. Keep `observe` on during and after the flip for continued visibility.

## Relevant Files

- `internal/config/config.go` — add `EgressAllowlist` struct + `Config` field.
- `internal/handlers/egress_allowlist.go` (new) + `_test.go` — handler logic.
- `internal/handlers/egress_allowlist_defaults.go` (new) — per-ecosystem tables.
- `proxy.go` — register handler; mirror the `blockMetadataAPIHosts` pattern.
- `internal/helpers/helpers.go` — reuse `GetHost`/`AreHostnamesEqual`; add a subdomain-suffix matcher.
- `internal/handlers/test_helpers.go` — `testGitSourceCred` etc. for tests.

## Verification

1. **Unit:** allowed host passes; both flags false ⇒ allow-all; `observe` only ⇒ logs + allows; `enforce` ⇒ 403; `observe`+`enforce` ⇒ logs + 403; credential-derived host allowed; subdomain suffix match; GitHub/API infra allowed; ecosystem default allowed for the job's `PACKAGE_MANAGER`.
2. **Config:** `egress_allowlist` JSON round-trips (`observe`, `enforce`, `domains`).
3. **Integration** (`proxy_test.go`): request to a non-allowlisted host returns 403 under `enforce`, passes (with log) under `observe`.
4. `go test ./...` then `script/test` (race, `-count=2`).

## Scope

**In:** host/domain allowlist, per-ecosystem defaults, config extras, credential-derived hosts, independent `observe` + `enforce` flags, 403 response.

**Out:** method/path filtering, open-redirect mitigation, DNS-takeover verification, and the `dependabot-api` backend changes that would populate `egress_allowlist.domains` (separate, dependent work item).

## Open Questions

1. **Enforcement targeting** — decide in the proxy (via `PACKAGE_MANAGER`) or have the backend set `enforce` per job? Recommend **backend-driven** so rollout can be ramped without redeploying the proxy.
2. **Response code** — settled on **403 Forbidden**, consistent with the existing 403 for blocked IPs. Distinguish allowlist drops from IP blocks via the log line / response body rather than a novel status code.
3. **Credential/GitHub hosts** — recommend they are **always implicitly allowed** to avoid accidental self-lockout.
