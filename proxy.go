package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/rs/dnscache"

	"github.com/dependabot/proxy/internal/apiclient"
	"github.com/dependabot/proxy/internal/cache"
	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/dialer"
	"github.com/dependabot/proxy/internal/handlers"
	"github.com/dependabot/proxy/internal/metrics"
)

// defaultCacheDir is the on-disk location used to cache proxied responses in production.
const defaultCacheDir = "/cache"

type Proxy struct {
	*goproxy.ProxyHttpServer
	metricsClient *metrics.CollectorClient
	Close         func() error
}

func newProxy(envSettings config.ProxyEnvSettings, cfg *config.Config, blockedIps []net.IP) *Proxy {
	return newProxyWithCacheDir(envSettings, cfg, blockedIps, defaultCacheDir)
}

func newProxyWithCacheDir(envSettings config.ProxyEnvSettings, cfg *config.Config, blockedIps []net.IP, cacheDir string) *Proxy {
	var err error

	if err := setCA([]byte(cfg.CA.Cert), []byte(cfg.CA.Key)); err != nil {
		log.Fatal(err)
	}

	resolver := dnscache.Resolver{}
	safeDialer := dialer.New(&resolver, blockedIps)

	transport := &http.Transport{
		Dial:        safeDialer.Dial,
		DialContext: safeDialer.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		Proxy: http.ProxyFromEnvironment,
	}
	oidcClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	apiClient := apiclient.New(envSettings.APIEndpoint, envSettings.JobToken, envSettings.JobID, apiclient.WithTransport(transport))
	metricsClient := metrics.New(envSettings, apiClient)

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr = transport

	proxy.CertStore = newCertStore()

	proxy.OnResponse().DoFunc(handleForbidden)
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(normaliseHost)
	proxy.OnRequest().DoFunc(blockMetadataAPIHosts)
	logger := NewRequestLogger()
	proxy.OnRequest().DoFunc(logger.logRequest)
	proxy.OnResponse().DoFunc(logger.logResponse)

	egressAllowlistHandler := handlers.NewEgressAllowlistHandler(cfg, envSettings, metricsClient)
	proxy.OnRequest().DoFunc(egressAllowlistHandler.HandleRequest)

	nugetFeedHandler := handlers.NewNugetFeedHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(nugetFeedHandler.PrepareRequest)

	enableCache := os.Getenv("PROXY_CACHE") == "true"
	cacher, err := cache.New(enableCache, cacheDir)
	if err != nil {
		log.Fatal(err)
	}
	proxy.OnRequest().DoFunc(cacher.OnRequest)

	dependabotApiHandler := handlers.NewDependabotAPIHandler(envSettings)
	if dependabotApiHandler != nil {
		proxy.OnRequest().DoFunc(dependabotApiHandler.HandleRequest)
	}

	metricsHandler := metrics.NewHandler(metricsClient)
	proxy.OnRequest().DoFunc(metricsHandler.HandleRequest)
	proxy.OnResponse().DoFunc(metricsHandler.HandleResponse)

	gitHubAPIHandler := handlers.NewGitHubAPIHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(gitHubAPIHandler.HandleRequest)
	proxy.OnResponse().DoFunc(gitHubAPIHandler.HandleResponse)

	azureDevOpsAPIHandler := handlers.NewAzureDevOpsAPIHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(azureDevOpsAPIHandler.HandleRequest)

	gitServerHandler := handlers.NewGitServerHandler(cfg.Credentials, apiClient)
	proxy.OnRequest().DoFunc(gitServerHandler.HandleRequest)
	proxy.OnResponse().DoFunc(gitServerHandler.HandleResponse)

	npmRegistryHandler := handlers.NewNPMRegistryHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(npmRegistryHandler.HandleRequest)

	hexOrganizationHandler := handlers.NewHexOrganizationHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(hexOrganizationHandler.HandleRequest)

	hexRepositoryHandler := handlers.NewHexRepositoryHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(hexRepositoryHandler.HandleRequest)

	pythonHandler := handlers.NewPythonIndexHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(pythonHandler.HandleRequest)
	proxy.OnResponse().DoFunc(pythonHandler.HandleResponse)

	composerHandler := handlers.NewComposerHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(composerHandler.HandleRequest)

	dockerRegistryHandler := handlers.NewDockerRegistryHandler(cfg.Credentials, oidcClient, nil)
	proxy.OnRequest().DoFunc(dockerRegistryHandler.HandleRequest)

	rubyGemsServerHandler := handlers.NewRubyGemsServerHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(rubyGemsServerHandler.HandleRequest)

	proxy.OnRequest().DoFunc(nugetFeedHandler.HandleRequest)
	proxy.OnResponse().DoFunc(nugetFeedHandler.HandleResponse)

	mavenRepositoryHandler := handlers.NewMavenRepositoryHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(mavenRepositoryHandler.HandleRequest)

	terraformRegistryHandler := handlers.NewTerraformRegistryHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(terraformRegistryHandler.HandleRequest)

	openTofuRegistryHandler := handlers.NewOpenTofuRegistryHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(openTofuRegistryHandler.HandleRequest)

	pubRepositoryHandler := handlers.NewPubRepositoryHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(pubRepositoryHandler.HandleRequest)

	cargoRegistryHandler := handlers.NewCargoRegistryHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(cargoRegistryHandler.HandleRequest)

	goProxyServerHandler := handlers.NewGoProxyServerHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(goProxyServerHandler.HandleRequest)

	helmRegistryHandler := handlers.NewHelmRegistryHandler(cfg.Credentials, oidcClient)
	proxy.OnRequest().DoFunc(helmRegistryHandler.HandleRequest)

	proxy.OnResponse().DoFunc(cacher.OnResponse)

	return &Proxy{
		ProxyHttpServer: proxy,
		metricsClient:   metricsClient,
		Close: func() error {
			metricsClient.StopBatchProcess()
			if cacher != nil {
				cacher.Statistics()
				return cacher.WriteToDisk()
			}
			return nil
		},
	}
}

func handleForbidden(rsp *http.Response, proxyCtx *goproxy.ProxyCtx) *http.Response {
	if errors.Is(proxyCtx.Error, dialer.ErrForbiddenRequest) {
		return goproxy.NewResponse(proxyCtx.Req, goproxy.ContentTypeText, http.StatusForbidden, "")
	}
	return rsp
}

func normaliseHost(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	req.URL.Host = strings.ToLower(req.URL.Host)
	req.Host = strings.ToLower(req.Host)
	return req, nil
}

const (
	metadataAPIHost = "metadata.google.internal"
)

func blockMetadataAPIHosts(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.Host == metadataAPIHost || req.URL.Host == metadataAPIHost {
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Forbidden")
	}
	return req, nil
}
