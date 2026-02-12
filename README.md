# Dependabot Proxy

The Dependabot Proxy is an HTTP and HTTPS proxy that adds authentication to requests to the GitHub API and to private package registries.
It is used by the [`dependabot-core`][dependabot-core] to handle authentication for various package managers and Git servers.

## Requirements

To build and run the proxy, you need to have the following installed:

- [Go][go] (version 1.26 or later)
- [Docker][docker]

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

[dependabot-core]: https://github.com/dependabot/dependabot-core
[docker]: https://docs.docker.com/get-docker/
[go]: https://golang.org/doc/install
