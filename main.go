package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/version"
	"github.com/evalphobia/logrus_sentry"
	"github.com/getsentry/raven-go"
	"github.com/sirupsen/logrus"
)

var (
	addr        = flag.String("addr", ":1080", "proxy listen address")
	configPath  = flag.String("config", "config.json", "configurations file path, use '-' for stdin")
	logfilePath = flag.String("logfile", "", "write logs to file")

	metadataAPIIPV4 = net.ParseIP("169.254.169.254")
	metadataAPIIPV6 = net.ParseIP("fd00:ec2::254")
	blockedIPs      = []net.IP{metadataAPIIPV4, metadataAPIIPV6}
)

func main() {
	flag.Parse()
	file := setupLogging()
	if file != nil {
		defer file.Close()
	}
	logrus.Info("proxy starting, commit: " + version.GitCommit)

	cfg, err := config.Parse(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	sentry, err := setupSentry()
	if err != nil {
		log.Fatal(err)
	}

	envSettings := config.ProxyEnvSettings{
		APIEndpoint:    os.Getenv("DEPENDABOT_API_URL"),
		PackageManager: os.Getenv("PACKAGE_MANAGER"),
		GroupedUpdate:  os.Getenv("GROUPED_UPDATE"),
		JobID:          os.Getenv("JOB_ID"),
		JobToken:       os.Getenv("JOB_TOKEN"),
	}

	proxy := newProxy(envSettings, cfg, blockedIPs)

	var handler http.Handler
	if sentry {
		handler = raven.Recoverer(proxy)
	} else {
		handler = proxy
	}

	server := &http.Server{
		Addr:    *addr,
		Handler: handler,
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		// First, flush the metrics data
		if proxy.metricsClient != nil {
			proxy.metricsClient.StopBatchProcess()
		}

		// Then, shutdown the server
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err = server.Shutdown(ctx); err != nil {
			log.Println("Error while shutting down proxy:", err)
		}
	}()

	log.Printf("Listening (%s)", *addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}

	if err := proxy.Close(); err != nil {
		log.Fatal(err)
	}
}

func setupSentry() (bool, error) {
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		return false, nil
	}
	if err := raven.SetDSN(dsn); err != nil {
		return false, fmt.Errorf("starting sentry: %w", err)
	}
	raven.SetRelease(version.GitCommit)
	raven.DefaultClient.Tags = map[string]string{
		"component": "dependabot-proxy",
	}
	if jobID := os.Getenv("JOB_ID"); jobID != "" {
		logrus.AddHook(&injectJobIDHook{JobID: jobID})
	}

	hook, err := logrus_sentry.NewWithClientSentryHook(raven.DefaultClient, []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
	})
	if err != nil {
		return false, fmt.Errorf("initializing sentry logrus hook: %w", err)
	}
	hook.Timeout = 5 * time.Second
	hook.StacktraceConfiguration.Enable = true
	logrus.AddHook(hook)
	return true, nil
}

type injectJobIDHook struct {
	JobID string
}

func (i injectJobIDHook) Levels() []logrus.Level { return logrus.AllLevels }

func (i injectJobIDHook) Fire(e *logrus.Entry) error {
	e.Data["job_id"] = i.JobID
	return nil
}


