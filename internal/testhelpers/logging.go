package testhelpers

import (
	"io"
	"log"
	"testing"

	"github.com/sirupsen/logrus"
)

// PreserveGlobalLoggerState restores the process-wide standard and Logrus
// logger configuration after the test completes.
func PreserveGlobalLoggerState(t testing.TB) {
	t.Helper()

	standardOutput := log.Writer()
	standardFlags := log.Flags()
	standardPrefix := log.Prefix()
	logrusLogger := logrus.StandardLogger()
	logrusOutput := logrusLogger.Out
	logrusFormatter := logrusLogger.Formatter
	logrusLevel := logrusLogger.GetLevel()
	logrusReportCaller := logrusLogger.ReportCaller

	t.Cleanup(func() {
		log.SetOutput(standardOutput)
		log.SetFlags(standardFlags)
		log.SetPrefix(standardPrefix)
		logrus.SetOutput(logrusOutput)
		logrus.SetFormatter(logrusFormatter)
		logrus.SetLevel(logrusLevel)
		logrus.SetReportCaller(logrusReportCaller)
	})
}

// CaptureStandardLog redirects the standard logger for the duration of a test.
func CaptureStandardLog(t testing.TB, output io.Writer) {
	t.Helper()
	PreserveGlobalLoggerState(t)
	log.SetOutput(output)
}

// CaptureGlobalLogs redirects the standard and Logrus loggers for a test.
func CaptureGlobalLogs(t testing.TB, output io.Writer) {
	t.Helper()
	PreserveGlobalLoggerState(t)
	log.SetOutput(output)
	logrus.SetOutput(output)
}
