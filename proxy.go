package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/rs/dnscache"

	"github.com/dependabot/proxy/internal/apiclient"
	"github.com/dependabot/proxy/internal/cache"
	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/dialer"
	"github.com/dependabot/proxy/internal/handlers"
	"github.com/dependabot/proxy/internal/metrics"
)

type Proxy struct {
	*goproxy.ProxyHttpServer
	metricsClient *metrics.CollectorClient
	Close         func() error
}

func newProxy(envSettings config.ProxyEnvSettings, cfg *config.Config, blockedIps []net.IP) *Proxy {
	var err error

	if err := setCA([]byte(cfg.CA.Cert), []byte(cfg.CA.Key)); err != nil {
		log.Fatal(err)
	}

	resolver := dnscache.Resolver{}
	safeDialer := dialer.New(&resolver, blockedIps)

	transport := &http.Transport{
		Dial:            safeDialer.Dial,
		DialContext:     safeDialer.DialContext,
		TLSClientConfig: &tls.Config{},
		Proxy:           http.ProxyFromEnvironment,
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

	enableCache := os.Getenv("PROXY_CACHE") == "true"
	cacher, err := cache.New(enableCache, "/cache")
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

	npmRegistryHandler := handlers.NewNPMRegistryHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(npmRegistryHandler.HandleRequest)

	hexOrganizationHandler := handlers.NewHexOrganizationHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(hexOrganizationHandler.HandleRequest)

	hexRepositoryHandler := handlers.NewHexRepositoryHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(hexRepositoryHandler.HandleRequest)

	pythonHandler := handlers.NewPythonIndexHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(pythonHandler.HandleRequest)

	composerHandler := handlers.NewComposerHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(composerHandler.HandleRequest)

	dockerRegistryHandler := handlers.NewDockerRegistryHandler(cfg.Credentials, transport, nil)
	proxy.OnRequest().DoFunc(dockerRegistryHandler.HandleRequest)

	rubyGemsServerHandler := handlers.NewRubyGemsServerHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(rubyGemsServerHandler.HandleRequest)

	nugetFeedHandler := handlers.NewNugetFeedHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(nugetFeedHandler.HandleRequest)

	mavenRepositoryHandler := handlers.NewMavenRepositoryHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(mavenRepositoryHandler.HandleRequest)

	terraformRegistryHandler := handlers.NewTerraformRegistryHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(terraformRegistryHandler.HandleRequest)

	pubRepositoryHandler := handlers.NewPubRepositoryHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(pubRepositoryHandler.HandleRequest)

	cargoRegistryHandler := handlers.NewCargoRegistryHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(cargoRegistryHandler.HandleRequest)

	goProxyServerHandler := handlers.NewGoProxyServerHandler(cfg.Credentials)
	proxy.OnRequest().DoFunc(goProxyServerHandler.HandleRequest)

	helmRegistryHandler := handlers.NewHelmRegistryHandler(cfg.Credentials)
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

func handleForbidden(rsp *http.Response, p *goproxy.ProxyCtx) *http.Response {
	if errors.Is(p.Error, dialer.ErrForbiddenRequest) {
		return goproxy.NewResponse(p.Req, goproxy.ContentTypeText, http.StatusForbidden, "")
	}
	return rsp
}

func normaliseHost(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	req.URL.Host = strings.ToLower(req.URL.Host)
	req.Host = strings.ToLower(req.Host)
	return req, nil
}

const (
	metadataAPIHost = "metadata.google.internal"
)

func blockMetadataAPIHosts(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.Host == metadataAPIHost || req.URL.Host == metadataAPIHost {
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Forbidden")
	}
	return req, nil
}
