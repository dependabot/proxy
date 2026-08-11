# Dependabot Proxy

The Dependabot Proxy is an HTTP and HTTPS proxy that adds authentication to requests to the GitHub API and to private package registries.
It is used by the [`dependabot-core`][dependabot-core] to handle authentication for various package managers and Git servers.

## Architecture

### goproxy Integration

The Dependabot Proxy is built on top of [elazarl/goproxy][goproxy], which provides the core HTTP/HTTPS proxy functionality:

- **HTTP/TLS handling** — goproxy manages low-level HTTP request parsing, TLS negotiation (MITM via `AlwaysMitm`), certificate generation, and connection lifecycle. The Proxy configures a custom `http.Transport` with TLS 1.2+ and a safe dialer, then assigns it to `goproxy.ProxyHttpServer.Tr`.
- **Request/response pipeline** — The Proxy registers handler functions via `proxy.OnRequest().DoFunc()` and `proxy.OnResponse().DoFunc()`. Each handler inspects requests by host, scheme, and method, then injects the appropriate authentication headers (****** Basic auth, or registry-specific credentials).
- **Upstream communication** — All outbound traffic from Dependabot updaters flows through the Proxy, which forwards requests via goproxy for routing and transport. Responses return through the same chain.

#### Data Flow

```
Dependabot updater → Proxy → goproxy → registry / Git server
                                ↓
                          (TLS, transport,
                           connection mgmt)
                                ↓
Dependabot updater ← Proxy ← goproxy ← registry / Git server
```

The Proxy injects credentials, CA bundles, and destination-specific authentication at the handler layer, while goproxy handles transport-level concerns underneath.

#### Upgrade Considerations

When updating the goproxy dependency, be aware that changes to its transport behaviour, TLS handling, or request lifecycle may affect Proxy functionality. In particular:

- Retry semantics and connection reuse are governed by goproxy's transport layer.
- TLS SNI is sent automatically by Go's `http.Transport` when `TLSClientConfig.ServerName` is empty.
- Cargo sparse index requests and other ecosystem-specific patterns may be sensitive to changes in how goproxy handles HTTP/2 or content negotiation.

[goproxy]: https://github.com/elazarl/goproxy

## Requirements

To build and run the proxy, you need to have the following installed:

- [Go][go] (version 1.26 or later)
- [Docker][docker]

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

[dependabot-core]: https://github.com/dependabot/dependabot-core
[docker]: https://docs.docker.com/get-docker/
[go]: https://golang.org/doc/install
