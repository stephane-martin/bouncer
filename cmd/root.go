package cmd

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

var ConfigDir string
var LogLevel string
var LogFilename string
var PidFilename string
var Syslog bool
var Json bool

var RootCmd = &cobra.Command{
	Use:   "nginx-auth-ldap",
	Short: "HTTP Basic Authentication with LDAP backend for nginx",
	Long: `nginx-auth-ldap implements HTTP Basic Authentication with an LDAP
backend for Nginx. It uses 'ngx_http_auth_request_module' module to perform
the authentication.`,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(init_logging)
	RootCmd.PersistentFlags().StringVar(&ConfigDir, "config", "", "the configuration directory to search")
	RootCmd.PersistentFlags().StringVar(&LogLevel, "loglevel", "info", "set logging level")
	RootCmd.PersistentFlags().StringVar(&LogFilename, "logfile", "", "if specified, write logs to that file instead of stdout/stderr")
	RootCmd.PersistentFlags().StringVar(&PidFilename, "pidfile", "", "if specified, write PID there")
	RootCmd.PersistentFlags().BoolVar(&Syslog, "syslog", false, "if specified, send logs to the local syslog instead of stdout/stderr")
	RootCmd.PersistentFlags().BoolVar(&Json, "json", false, "if specified, write logs in JSON format")	
}

func init_logging() {
	if Json {
		log.Log.Formatter = &logrus.JSONFormatter{}
	}

	lvl, err := logrus.ParseLevel(LogLevel)
	if err != nil {
		log.Log.WithError(err).WithField("loglevel", LogLevel).Warn("Unknown log level. Selecting INFO instead.")
		log.Log.Level = logrus.InfoLevel
	} else {
		log.Log.Level = lvl
	}
}
