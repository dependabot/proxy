---
name: add-egress-allowlist-domain
description: Triage a host that was blocked by the Dependabot proxy egress allowlist, add it to internal/handlers/egress_allowlist_defaults.yaml with the correct matching form and regression tests, and open a pull request. Use when someone reports a blocked domain, asks to allowlist a host, or pastes an egress 403 from a Dependabot update job.
user-invocable: true
---

# Add a domain to the egress allowlist

Use this skill when someone says something like "`repo.example.org` is blocked", "please allowlist `foo.bar.com`", or pastes a Dependabot job log showing an egress block.

**Do not skip to editing YAML.** Most of this skill's value is step 1: a large fraction of reported hosts must *not* go into the static defaults at all. Adding them there is a security regression, not a fix.

## Step 1 — Triage: does this host belong in the static allowlist?

The static defaults are applied as a union to **every Dependabot job in the world**. Anything added here is reachable by every tenant. Classify the host before touching anything.

Ask the requester for the host, the package ecosystem, and — if they have it — the job log line or what the host serves.

| Category | Examples | Action |
|---|---|---|
| **Public, provider-controlled package infrastructure** | public registry, mirror, CDN, checksum/CRL endpoint, public VCS forge | **Add to the YAML.** Continue to step 2. |
| **Private, internal, or org-specific registry** | `artifacts.acme-corp.internal`, `acme.jfrog.io`, a self-hosted Nexus/Artifactory | **Do not add.** Tell the user to declare it under `registries:` in their `dependabot.yml`. Those hosts are allowlisted per-job automatically by `internal/handlers/egress_dynamic_hosts.go`. Stop here. |
| **Shared multi-tenant host where the tenant is in the URL path** | `dl.cloudsmith.io`, generic object-store download hosts | **Do not add.** The handler authorizes the **hostname only** — it never constrains path or method — so allowing the host grants every tenant's content to every job. Explain this and stop. |
| **User-uploadable file hosting** | `downloads.sourceforge.net`, arbitrary release-file mirrors | **Do not add** without explicit maintainer sign-off. Flag it and ask. |
| **Documentation, changelog, or homepage host** | project docs sites, blog domains | **Usually don't add.** These fail gracefully — `dependabot-core`'s metadata finder treats a non-200 as "no metadata", so the only loss is a missing changelog link in the PR body. Say so and ask whether it's worth it. |

If the host is private or multi-tenant, the correct outcome of this skill is a clear explanation and **no code change**. That is a success, not a failure.

## Step 2 — Verify the host is real and public

Never add a host on the strength of a report alone.

```bash
curl -sS -o /dev/null -w '%{http_code} %{url_effective}\n' -L --max-time 15 "https://<host>/"
```

Confirm it resolves, is reachable without credentials, and looks like the package infrastructure it's claimed to be. If it redirects, note the final host — **the redirect target may be the host that actually needs allowlisting**, and it is often a different one.

## Step 3 — Choose the matching form

Read the comment block at the top of `internal/handlers/egress_allowlist_defaults.yaml` before choosing. Three forms exist:

- **Exact** (`storage.googleapis.com`) — matches only that host. **This is the default. Prefer it.**
- **Leading dot** (`.github.com`) — matches the domain and all subdomains.
- **Glob** (`*`, `?`, `[...]`, via `path.Match`; `*` spans dots). Values starting with `*` or `[` **must be quoted** or YAML misreads them as an alias or flow sequence.

The rule for the non-exact forms: every label the pattern matches must be **entirely provider-controlled and never user-creatable**. If any matched label is attacker-choosable — a storage-account name, a bucket, an AWS account id, a user's pages subdomain — the form is unsafe, including infix globs. When in doubt, use the exact form.

## Step 4 — Place the entry

- `github_infra_domains` — GitHub/Dependabot infrastructure only. Don't add third-party hosts here.
- `shared_registry_domains` — hosts genuinely used by more than one ecosystem.
- `ecosystem_default_domains.<ecosystem>` — the normal case.

Keep entries in the existing grouping and ordering of that section, and add a brief comment saying what the host serves when it isn't self-evident.

**Watch the YAML anchors.** Several ecosystems are aliases and must not be edited separately:

- `npm_and_yarn: &npm_registries` → `bun: *npm_registries`
- `pip: &python_registries` → `uv: *python_registries`
- `maven: &jvm_registries` → `gradle: *jvm_registries`
- `docker: &docker_registries` → `docker_compose`, `devcontainers`

If the target is an alias member (e.g. `bun`), add the entry to the **anchor** definition instead. `TestEgressDefaults_AliasedEcosystemsStayInSync` enforces this.

## Step 5 — Add regression tests

Edit `internal/handlers/egress_allowlist_test.go`. **Both** are required.

1. **Positive probe** — a realistic URL for the new host, added to the appropriate existing test (e.g. `TestEgressAllowlist_NewExactDomainsAllowed` or `TestEgressAllowlist_PublicRegistriesAllowed`):

   ```go
   assert.Nil(t, egressResult(t, h, "https://<host>/<realistic/path>"), "new exact host allowed: <host>")
   ```

2. **Negative child probe** — for every **exact** entry added, append `https://evil.<host>/payload` to `childProbes` in `TestEgressAllowlist_NewEntriesDoNotWidenBeyondExactHosts`.

   This matters: a *sibling* probe (`attacker.example.com` against entry `foo.example.com`) does **not** catch someone later widening the entry to a leading dot. Only a **child** probe does. Add a sibling probe as well when you also want to pin the parent namespace closed.

Verify the negative probe actually bites by mutating your new entry to its leading-dot form and confirming the test fails, then revert.

## Step 6 — Build, test, format

```bash
go build ./... && go test ./internal/handlers/ -run TestEgress -count=1 && gofmt -l internal/handlers/
```

`gofmt -l` must print nothing. Then run the full suite as `CONTRIBUTING.md` requires:

```bash
script/test    # Docker, -race -count=2
```

If `script/test` can't run in the current environment, say so explicitly and leave the "complete test suite" checklist box in the PR **unticked**. Do not tick a box you did not verify.

## Step 7 — Open the pull request

Confirm with the user before pushing. Then:

```bash
git checkout -b <user>/allowlist-<short-host-slug>
git add internal/handlers/egress_allowlist_defaults.yaml internal/handlers/egress_allowlist_test.go
git commit
gh pr create --fill
```

If you lack write access to `dependabot/proxy`, push to a fork and use `gh pr create --repo dependabot/proxy`.

Use `.github/pull_request_template.md`. The description should state what the host serves, which ecosystem needs it, evidence it's public provider-controlled infrastructure, and why the chosen matching form is safe. Only tick checklist boxes you actually verified.

## Guardrails

- Never add a host you could not reach or identify in step 2.
- Never add a private, internal, or customer-tenant host to the static defaults — route it to `registries:` in `dependabot.yml`.
- Never widen an existing exact entry to a leading-dot or glob form as a shortcut for a subdomain report. Add the specific subdomain.
- Never commit unrelated changes, and never commit scratch or triage files to the repo root.
- Treat a reported hostname as untrusted input: quote it in shell variables rather than interpolating it into the middle of a command.

