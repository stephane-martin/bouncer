package cmd

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/facebookgo/pidfile"
	cache "github.com/patrickmn/go-cache"
	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/auth"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP server",
	Long: `Start the HTTP server responsible to answer Nginx authentication
subrequests.`,
	Run: func(cmd *cobra.Command, args []string) {
		serve()
	},
}

func init() {
	RootCmd.AddCommand(serveCmd)
}

var auth_cache *cache.Cache
var secret []byte

func serve() {
	disable_timestamps := false
	disable_colors := false

	if Syslog || len(LogFilename) > 0 {
		disable_timestamps = true
		disable_colors = true
	}

	if Json {
		log.Log.Formatter = &logrus.JSONFormatter{DisableTimestamp: disable_timestamps}
	} else {
		log.Log.Formatter = &logrus.TextFormatter{DisableColors: disable_colors, DisableTimestamp: disable_timestamps, FullTimestamp: true}
	}

	if Syslog {
		hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, "")
		if err == nil {
			log.Log.Hooks.Add(hook)
			f, err := os.OpenFile("/dev/null", os.O_WRONLY, 0600)
			if err == nil {
				log.Log.Out = f
				defer f.Close()
			}
		} else {
			log.Log.WithError(err).Error("Unable to connect to local syslog daemon")
		}
	}

	if len(LogFilename) > 0 {
		f, err := os.OpenFile(LogFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
		if err != nil {
			log.Log.WithError(err).WithField("logfile", LogFilename).Fatal("Failed to open the log file")
		}
		defer f.Close()
		log.Log.Out = f
	}

	if len(PidFilename) > 0 {
		pidfile.SetPidfilePath(PidFilename)
		err := pidfile.Write()
		if err != nil {
			log.Log.WithError(err).Fatal("Error writing PID file")
		}
		defer func() {
			os.Remove(PidFilename)
		}()
	}

	restart := true
	for restart {
		config, err := conf.Load(ConfigDir)
		if err != nil {
			log.Log.WithError(err).Error("Error loading configuration")
			os.Exit(-1)
		}

		if config.Cache.Expires > 0 {
			expires := time.Duration(config.Cache.Expires) * time.Second
			auth_cache = cache.New(expires, 10*expires)
			if len(config.Cache.Secret) == 0 {
				secret = make([]byte, 32)
				_, err := rand.Read(secret)
				if err != nil {
					log.Log.WithError(err).Error("Error generating a secret")
					os.Exit(-1)
				}
			} else {
				secret = []byte(config.Cache.Secret)
			}
		}

		sig_chan := make(chan os.Signal, 1)
		signal.Notify(sig_chan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

		server, done := start_server(config)
		select {

		case <-done:
			// abrupt termination of the HTTP server
			signal.Stop(sig_chan)
			close(sig_chan)
			restart = false

		case sig := <-sig_chan:
			signal.Stop(sig_chan)
			close(sig_chan)

			var c context.Context
			var f context.CancelFunc
			if config.Http.ShutdownTimeout > 0 {
				c, f = context.WithTimeout(context.Background(), time.Duration(config.Http.ShutdownTimeout)*time.Second)
				defer f()
			}

			switch sig {
			case syscall.SIGTERM:
				log.Log.Info("SIGTERM received")
				server.Shutdown(c)
				<-done
				restart = false
			case syscall.SIGINT:
				log.Log.Info("SIGINT received")
				server.Shutdown(c)
				<-done
				restart = false
			case syscall.SIGHUP:
				log.Log.Info("SIGHUP received: reloading configuration and restart the HTTP server")
				server.Shutdown(c)
				<-done
			default:
				server.Shutdown(c)
				<-done
				restart = false
			}
		}
		close(done)

	}
}

func start_server(config *conf.GlobalConfig) (*http.Server, chan bool) {

	handler := func(w http.ResponseWriter, r *http.Request) {
		var mac_bytes []byte

		authorization := strings.TrimSpace(r.Header.Get(config.Http.AuthorizationHeader))
		original_uri := strings.TrimSpace(r.Header.Get(config.Http.OriginalUriHeader))
		realm := fmt.Sprintf("Basic realm=\"%s\"", config.Http.Realm)

		if len(authorization) == 0 {
			log.Log.Debug("No Authorization header in request")
			w.Header().Add(config.Http.AuthenticateHeader, realm)
			w.WriteHeader(401)
			return
		}
		splits := strings.Split(authorization, " ")
		if len(splits) != 2 {
			log.Log.Debug("Authorization header is present but has a bad format")
			w.WriteHeader(400)
			return
		}
		if splits[0] != "Basic" {
			log.Log.Debug("Authorization header is present but does not begin with 'Basic'")
			w.WriteHeader(400)
			return
		}
		encoded := splits[1]
		if len(encoded) == 0 {
			log.Log.Debug("The encoded base64 is empty")
			w.WriteHeader(400)
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			log.Log.Debug("Not properly base64 encoded")
			w.WriteHeader(400)
			return
		}
		splits = strings.Split(string(decoded), ":")
		if len(splits) != 2 {
			log.Log.Debug("The decoded base64 does not contain a ':'")
			w.WriteHeader(400)
			return
		}
		username := strings.TrimSpace(splits[0])
		password := strings.TrimSpace(splits[1])
		if len(username) == 0 || len(password) == 0 {
			log.Log.Debug("Empty username or empty password")
			w.Header().Add(config.Http.AuthenticateHeader, realm)
			w.WriteHeader(401)
			return
		}
		if auth_cache != nil {
			mac := hmac.New(sha256.New, secret)
			mac.Write(decoded)
			mac_bytes = mac.Sum(nil)
			cached_item, found := auth_cache.Get(username)
			if found {
				if hmac.Equal(mac_bytes, cached_item.([]byte)) {
					log.Log.WithField("username", username).WithField("uri", original_uri).Debug("Auth is successfull (cached)")
					w.WriteHeader(200)
					return
				}
			}

		}

		err = auth.Authenticate(username, password, config)
		if err == nil {
			log.Log.WithField("username", username).WithField("uri", original_uri).Debug("Auth is successfull")
			if auth_cache != nil {
				auth_cache.Add(username, mac_bytes, cache.DefaultExpiration)
			}
			w.WriteHeader(200)
			return
		} else {
			log.Log.WithError(err).WithField("username", username).WithField("uri", original_uri).Info("Auth failed")
			if config.Http.FailedAuthDelay > 0 {
				time.Sleep(time.Duration(config.Http.FailedAuthDelay) * time.Second)
			}
			w.Header().Add(config.Http.AuthenticateHeader, realm)
			w.WriteHeader(401)
			return
		}
	}

	done := make(chan bool, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.Http.BindAddr, config.Http.Port),
		Handler: mux,
	}

	go func() {
		log.Log.WithField("bind", server.Addr).Info("Starting HTTP server")
		var err error
		if config.Http.Https {
			err = server.ListenAndServeTLS(config.Http.Certificate, config.Http.Key)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil {
			switch err := err.(type) {
			default:
				log.Log.WithError(err).Info("HTTP server error. Probably normal.")
			case *net.OpError:
				log.Log.WithError(err).Error("HTTP server operational error")
			}
		}
		done <- true
	}()

	return server, done

}
