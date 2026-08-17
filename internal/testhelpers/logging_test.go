package testhelpers

import (
	"io"
	"log"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestPreserveGlobalLoggerState(t *testing.T) {
	standardOutput := log.Writer()
	standardFlags := log.Flags()
	standardPrefix := log.Prefix()
	logrusLogger := logrus.StandardLogger()
	logrusOutput := logrusLogger.Out
	logrusFormatter := logrusLogger.Formatter
	logrusLevel := logrusLogger.GetLevel()
	logrusReportCaller := logrusLogger.ReportCaller

	t.Run("mutate logger state", func(t *testing.T) {
		PreserveGlobalLoggerState(t)
		log.SetOutput(io.Discard)
		log.SetFlags(0)
		log.SetPrefix("test-prefix")
		logrus.SetOutput(io.Discard)
		logrus.SetFormatter(&logrus.JSONFormatter{})
		logrus.SetLevel(logrus.DebugLevel)
		logrus.SetReportCaller(!logrusReportCaller)
	})

	assert.Equal(t, standardOutput, log.Writer())
	assert.Equal(t, standardFlags, log.Flags())
	assert.Equal(t, standardPrefix, log.Prefix())
	assert.Equal(t, logrusOutput, logrusLogger.Out)
	assert.Equal(t, logrusFormatter, logrusLogger.Formatter)
	assert.Equal(t, logrusLevel, logrusLogger.GetLevel())
	assert.Equal(t, logrusReportCaller, logrusLogger.ReportCaller)
}
