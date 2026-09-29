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

**This step is the gate.** Only a host you have classified as public, provider-controlled infrastructure proceeds to step 2. Step 2 does not revisit this decision — it cannot (see the warning there) — so a misclassification here is never caught later.

### Signals that a host is a private or tenant-specific registry

These are not proof, but each should send you back to the table above:

- **A wildcard certificate whose parent domain is a known multi-tenant provider** — `CN=*.jfrog.io`, `CN=*.cloudsmith.io`, `CN=*.fury.io`, `CN=*.myget.org`. This shows the *provider* owns the domain; it says nothing about the tenant being public. Note the inverse is not a signal: `*.julialang.org` and `*.huaweicloud.com` are wildcards on genuinely public infrastructure, so judge the parent domain, not the wildcard.
- **A redirect to a registry vendor's marketing site** — `package-manager.aa.com` and `dl.cloudsmith.io` both 302 to `https://cloudsmith.com/`. A private tenant fronted by a hosted registry commonly advertises its backing vendor this way.
- **An organisation name in the host** that matches the requester rather than an ecosystem (`artifactory.<company>.com`, `npm.<company>.com`, `<company>.jfrog.io`).
- **A credentialed response** — `401`/`403` on a real artifact path means the host expects authentication, which is what `registries:` is for.

## Step 2 — Confirm the host is safe to probe, and gather ownership evidence

> **A passing `verify_host` does NOT authorise an addition.** It answers "is it safe for *me* to send a request here?" — not "is this host public infrastructure?". Most private registries pass it: `package-manager.aa.com`, `dl.cloudsmith.io` and `centraluhg.jfrog.io` all resolve to public IPs and serve valid certificates. A private registry that is properly internet-facing is indistinguishable from public infrastructure at this layer. Step 1 is what decides; this step only keeps the probe itself safe and collects evidence for the PR.

Never add a host on the strength of a report alone.

A reported hostname is untrusted input. Validate it as a bare DNS hostname *before* it reaches any command, require every resolved address to be public, and walk redirects one hop at a time — `curl -L` will happily follow a public host to loopback, RFC1918, link-local, or metadata endpoints.

```bash
verify_host() {
  local host="$1" ip ips
  # Reject anything that is not a bare DNS hostname, before it reaches a command.
  if ! printf '%s' "$host" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
    echo "REJECT: not a bare DNS hostname"; return 1
  fi
  # Every resolved address must be public.
  ips=$(dig +short "$host" A; dig +short "$host" AAAA)
  ips=$(printf '%s\n' "$ips" | grep -E '^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F:]+)$')
  [ -z "$ips" ] && { echo "REJECT: does not resolve"; return 1; }
  for ip in $ips; do
    case "$ip" in
      10.*|127.*|0.*|169.254.*|192.168.*|::1|fc*|fd*|fe80*) echo "REJECT: non-public $ip"; return 1;;
      172.1[6-9].*|172.2[0-9].*|172.3[01].*) echo "REJECT: non-public $ip"; return 1;;
      100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) echo "REJECT: CGNAT $ip"; return 1;;
    esac
  done
  echo "OK: $host -> $(printf '%s' "$ips" | tr '\n' ' ')"
  # One hop at a time. Re-run verify_host on any next_hop before following it.
  curl -sS -o /dev/null --max-time 15 --proto '=https' --max-redirs 0 \
       -w '    status=%{http_code} next_hop=%{redirect_url}\n' "https://$host/<real/artifact/path>" || true
  # Ownership evidence, not just reachability.
  echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null \
    | openssl x509 -noout -subject -issuer 2>/dev/null | sed 's/^/    /'
}

verify_host '<host>'
```

Reachability alone is **not** sufficient evidence — it proves the host answers, not that the claimed provider controls it, and certainly not that it is public. Require authoritative corroboration: a TLS certificate whose subject/issuer belongs to the provider, an entry in a provider-published list such as `api.github.com/meta`, or the provider's own documentation. Check the certificate against the private-registry signals in step 1 before treating it as supporting evidence. A host that merely responds is not yet a candidate.

Probe a **real artifact path**, not `/`. Root probes mislead: `data.nuget.org/` 404s and `packages.atlassian.com/` 401s, while both serve packages correctly on their real paths.

If it redirects, re-run `verify_host` on the target before following it — **the redirect target may be the host that actually needs allowlisting**, and it is often a different one.

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
gh pr create --template .github/pull_request_template.md
```

`--template` opens the repository template for completion. Do not use `--fill`: it takes the title and body from commit data and skips template selection entirely, producing a PR that omits the required sections.

If you lack write access to `dependabot/proxy`, push to a fork and use `gh pr create --repo dependabot/proxy --template .github/pull_request_template.md`.

Complete every section of the template. The description should state what the host serves, which ecosystem needs it, the authoritative evidence that it is public provider-controlled infrastructure, and why the chosen matching form is safe. Only tick checklist boxes you actually verified.

## Guardrails

- Never add a host you could not reach in step 2, or for which you have no authoritative provider evidence. Reachability alone is not evidence of ownership.
- Never treat a passing `verify_host` as permission to add a host. It checks probe safety, not whether the host is public — private registries pass it routinely. Step 1 is the gate.
- Never interpolate a reported hostname into a command before validating it as a bare DNS hostname, and never follow redirects with `curl -L` during verification — validate each hop's address is public first.
- Never add a private, internal, or customer-tenant host to the static defaults — route it to `registries:` in `dependabot.yml`.
- Never widen an existing exact entry to a leading-dot or glob form as a shortcut for a subdomain report. Add the specific subdomain.
- Never commit unrelated changes, and never commit scratch or triage files to the repo root.
- Treat a reported hostname as untrusted input: quote it in shell variables rather than interpolating it into the middle of a command.

