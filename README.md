# Dependabot Proxy

The Dependabot Proxy is an HTTP and HTTPS proxy that adds authentication to requests to the GitHub API and to private package registries.
It is used by the [`dependabot-core`][dependabot-core] to handle authentication for various package managers and Git servers.

## Requirements

To build and run the proxy, you need to have the following installed:

- [Go][go] (version 1.26 or later)
- [Docker][docker]

## Image provenance

The `main` publish workflow builds `ghcr.io/dependabot/proxy` for `linux/amd64`.
The build pushes a `v2.0.YYYYMMDDHHMMSS` image tag and updates `latest`.
The workflow then publishes signed build provenance for the image digest to GitHub and GHCR.
After attestation succeeds, it creates the matching Git tag at the source commit.
If attestation fails, the image tags remain published and the workflow fails.

To verify an image, replace the placeholders with its digest and the expected source commit:

```bash
IMAGE_DIGEST='sha256:<digest>'
SOURCE_SHA='<commit>'

gh attestation verify "oci://ghcr.io/dependabot/proxy@${IMAGE_DIGEST}" \
  --repo dependabot/proxy \
  --signer-workflow dependabot/proxy/.github/workflows/ghcr.yml \
  --source-ref refs/heads/main \
  --source-digest "${SOURCE_SHA}"
```

The publication summary includes the digest, source commit and attestation link.
Add `--bundle-from-oci` to retrieve the attestation from GHCR instead of the GitHub API.

These attestations cover newly built container images. The workflow does not backfill historical images.
Runtime verification in the CLI and Action, and attestations for the native CodeQL archives, are separate work.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

[dependabot-core]: https://github.com/dependabot/dependabot-core
[docker]: https://docs.docker.com/get-docker/
[go]: https://golang.org/doc/install
