package cmd

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/syslog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/facebookgo/pidfile"
	"github.com/go-redis/redis"
	"github.com/hashicorp/errwrap"
	cache "github.com/patrickmn/go-cache"
	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/auth"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/janitor"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	"github.com/stephane-martin/nginx-auth-ldap/model"
	"github.com/stephane-martin/nginx-auth-ldap/stats"
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

func sighup() {
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(syscall.SIGHUP)
}

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

	// prevent SIGHUP to stop the program in all cases
	signal.Ignore(syscall.SIGHUP)

	restart := true
	for restart {
		restart = do_serve()
	}
}

func do_serve() bool {

	config, err := conf.Load(ConfigDir)
	if err != nil {
		log.Log.WithError(err).Error("Error loading configuration. Sleeping a while and restarting.")
		time.Sleep(time.Duration(30) * time.Second)
		return true
	}

	err = auth.CheckLdapConn(config)
	if err != nil {
		log.Log.WithError(err).Error("Connection to LDAP failed. Sleeping a while and restarting.")
		time.Sleep(time.Duration(30) * time.Second)
		return true
	}

	var redis_client *redis.Client
	var jan *janitor.Janitor
	if config.Redis.Enabled {
		err = config.CheckRedisConn()
		if err != nil {
			log.Log.WithError(err).Error("Connection to Redis failed. Stats won't be available.")
			config.Redis.Enabled = false
		} else if config.Redis.Expires > 0 {
			redis_client = config.GetRedisClient()
			jan = janitor.NewJanitor(config, redis_client)
			jan.Start()
			defer jan.Stop()
		}
	}

	// install signal handlers
	sig_chan := make(chan os.Signal, 1)
	signal.Notify(sig_chan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	var ctx context.Context
	var cancel_ctx context.CancelFunc
	if config.Http.ShutdownTimeout > 0 {
		ctx, cancel_ctx = context.WithTimeout(context.Background(), time.Duration(config.Http.ShutdownTimeout)*time.Second)
		defer cancel_ctx()
	}

	server, done := StartHttp(config, redis_client)
	api, api_done := StartApi(config, redis_client)

	select {
	// wait for either a signal, or that the HTTP server stops
	case <-done:
		// stop signal handlers
		signal.Stop(sig_chan)
		close(sig_chan)
		log.Log.Error("Abrupt termination of the HTTP server. Sleeping a while and restarting.")
		api.Shutdown(nil)
		<-api_done
		time.Sleep(time.Duration(30) * time.Second)
		return true


	case <-api_done:
		signal.Stop(sig_chan)
		close(sig_chan)
		log.Log.Error("Abrupt termination of the API server. Sleeping a while and restarting.")
		server.Shutdown(ctx)
		<-done
		time.Sleep(time.Duration(30) * time.Second)
		return true

	case sig := <-sig_chan:
		// stop signal handlers... in all cases
		signal.Stop(sig_chan)
		close(sig_chan)

		switch sig {
		case syscall.SIGTERM, syscall.SIGINT:
			log.Log.Info("SIGTERM received: stopping the HTTP servers")
			server.Shutdown(ctx)
			api.Shutdown(nil)
			<-done
			<-api_done
			return false
		case syscall.SIGHUP:
			log.Log.Info("SIGHUP received: reloading configuration and restart the HTTP servers")
			server.Shutdown(ctx)
			api.Shutdown(nil)
			<-done
			<-api_done
			return true
		default:
			server.Shutdown(ctx)
			api.Shutdown(nil)
			<-done
			<-api_done
			return false
		}
	}
}

func EventFromRequest(r *http.Request, config *conf.GlobalConfig) (e *model.Event) {
	e = model.NewEmptyEvent()
	authorization := strings.TrimSpace(r.Header.Get(config.Http.AuthorizationHeader))
	e.Host = strings.TrimSpace(r.Header.Get(config.Http.OriginalHostHeader))
	e.Uri = strings.TrimSpace(r.Header.Get(config.Http.OriginalUriHeader))
	e.Port = strings.TrimSpace(r.Header.Get(config.Http.OriginalPortHeader))
	e.Proto = strings.TrimSpace(r.Header.Get(config.Http.OriginalProtoHeader))

	if len(authorization) == 0 {
		e.RetCode = 401
		e.Result = model.NO_AUTH
		e.Message = "No Authorization header in request"
		return e
	}
	splits := strings.Split(authorization, " ")
	if len(splits) != 2 {
		e.RetCode = 400
		e.Result = model.INVALID_REQUEST
		e.Message = "Authorization header is present but has a bad format"
		return e
	}
	if splits[0] != "Basic" {
		e.RetCode = 400
		e.Result = model.INVALID_REQUEST
		e.Message = "Authorization header is present but does not begin with 'Basic'"
		return e
	}
	encoded := splits[1]
	if len(encoded) == 0 {
		e.RetCode = 400
		e.Result = model.INVALID_REQUEST
		e.Message = "The encoded base64 is empty"
		return e
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		e.RetCode = 400
		e.Result = model.INVALID_REQUEST
		e.Message = "Not properly base64 encoded"
		return e
	}
	splits = strings.Split(string(decoded), ":")
	if len(splits) != 2 {
		e.RetCode = 400
		e.Result = model.INVALID_REQUEST
		e.Message = "The decoded base64 does not contain a ':'"
		return e
	}
	e.Username = strings.TrimSpace(splits[0])
	e.Password = strings.TrimSpace(splits[1])
	if len(e.Username) == 0 || len(e.Password) == 0 {
		e.RetCode = 401
		e.Result = model.FAIL_AUTH
		e.Message = "Empty username or empty password"
		return e
	}
	return e
}

func StartApi(config *conf.GlobalConfig, redis_client *redis.Client) (*http.Server, chan bool) {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.Api.BindAddr, config.Api.Port),
		Handler: mux,
	}

	stats_mngr := stats.NewStats(redis_client)

	status_handler := func(w http.ResponseWriter, r *http.Request) {
		// just reply that the server is alive
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><head><title>nginx-auth-ldap</title></head><body><h1>nginx-auth-ldap is running</h1></body></html>"))
		return
	}

	check_handler := func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckLdapConn(config) != nil {
			// we have a connection problem to LDAP...
			// first reply that the health check is negative
			w.WriteHeader(500)
			// then send signal to myself to stop the HTTP server
			sighup()
		} else {
			// we're alive
			w.WriteHeader(200)
		}
	}

	reload_handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(200)
			sighup()
		} else {
			w.WriteHeader(400)
		}
	}

	config_handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(config.Export()))
	}

	auth_handler := func(w http.ResponseWriter, r *http.Request) {
		username := strings.TrimSpace(r.FormValue("username"))
		password := strings.TrimSpace(r.FormValue("password"))
		if len(username) == 0 || len(password) == 0 {
			w.WriteHeader(403)
			return
		}
		err := auth.Authenticate(username, password, config)
		if err == nil {
			w.WriteHeader(200)
			return
		}
		if errwrap.ContainsType(err, new(auth.LdapOpError)) {
			w.WriteHeader(500)
			log.Log.WithError(err).WithField("username", username).Error("LDAP operational error happened in /auth")
			sighup()
			return
		} else if errwrap.ContainsType(err, new(auth.LdapAuthError)) {
			w.WriteHeader(403)
			return
		} else {
			w.WriteHeader(500)
			log.Log.WithError(err).WithField("username", username).Error("Unexpected error happened in /auth")
			sighup()
			return
		}
	}

	stats_handler := func(w http.ResponseWriter, r *http.Request) {
		// report statistics

		all_ranges := map[string]int64{
			"last_day":  86400,
			"last_hour": 3600,
			"last_min":  60,
		}

		req_period := strings.TrimSpace(r.FormValue("period"))
		if len(req_period) != 0 {
			num_period, err := strconv.ParseInt(req_period, 10, 64)
			if err == nil {
				period_name := fmt.Sprintf("last_%d_seconds", num_period)
				all_ranges = map[string]int64{period_name: num_period}
			}
		}

		measurements, err := stats_mngr.GetMeasurements(all_ranges)
		if err != nil {
			log.Log.WithError(err).Error("Error querying stats in Redis")
			w.WriteHeader(500)
			return
		}

		out, err := measurements.Json()
		if err != nil {
			log.Log.WithError(err).Error("Error marshalling statistics to JSON")
			w.WriteHeader(500)
		} else {
			w.WriteHeader(200)
			w.Header().Set("Content-Type", "application/json")
			w.Write(out)
		}
	}

	mux.HandleFunc("/status", status_handler)
	mux.HandleFunc("/conf", config_handler)
	mux.HandleFunc("/check", check_handler)
	mux.HandleFunc("/auth", auth_handler)
	mux.HandleFunc("/reload", reload_handler)

	if config.Redis.Enabled {
		mux.HandleFunc("/stats", stats_handler)
	}

	done := make(chan bool, 1)
	go func() {
		log.Log.WithField("bind", server.Addr).Info("Starting HTTP server")
		err := server.ListenAndServe()
		if err != nil {
			switch err := err.(type) {
			default:
				log.Log.WithError(err).Info("API server error. (Probably normal)")
			case *net.OpError:
				log.Log.WithError(err).Error("API server operational error")
			}
		}
		done <- true
		close(done)
	}()

	return server, done

}

func StartHttp(config *conf.GlobalConfig, redis_client *redis.Client) (*http.Server, chan bool) {

	stats_mngr := stats.NewStats(redis_client)

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.Http.BindAddr, config.Http.Port),
		Handler: mux,
	}

	var secret []byte
	var err error
	var auth_cache *cache.Cache

	if config.Cache.Expires > 0 {
		expires := time.Duration(config.Cache.Expires) * time.Second
		auth_cache = cache.New(expires, 10*expires)
		secret, err = config.GenerateSecret()
		if err != nil {
			log.Log.WithError(err).Error("Error generating secret!!!")
			os.Exit(-1)
		}
	}

	main_handler := func(w http.ResponseWriter, r *http.Request) {
		var hmac_b []byte

		ev := EventFromRequest(r, config)

		defer func() {
			if ev.RetCode == 500 {
				sighup()
			}
		}()

		defer func() {
			l := log.Log.WithField("username", ev.Username).WithField("uri", ev.Uri).WithField("retcode", ev.RetCode).WithField("result", ev.Result)
			if ev.RetCode == 200 {
				l.Debug(ev.Message)
			} else if ev.RetCode == 500 {
				l.Warn(ev.Message)
			} else {
				l.Info(ev.Message)
			}
		}()

		if config.Redis.Enabled {
			defer stats_mngr.Store(ev)
		}

		defer func() {
			if ev.RetCode == 401 {
				w.Header().Add(config.Http.AuthenticateHeader, fmt.Sprintf("Basic realm=\"%s\"", config.Http.Realm))
			}
			w.WriteHeader(ev.RetCode)
		}()

		if ev.RetCode != 0 {
			return
		}

		if auth_cache != nil {
			hmac_b = ev.Hmac(secret)
			cached_hmac_b, found := auth_cache.Get(ev.Username)
			if found {
				if hmac.Equal(hmac_b, cached_hmac_b.([]byte)) {
					ev.Message = "Auth is successful (cached)"
					ev.Result = model.SUCCESS_AUTH_CACHE
					ev.RetCode = 200
					return
				}
			}
		}

		err := auth.Authenticate(ev.Username, ev.Password, config)
		if err == nil {
			ev.Message = "Auth is succesful (not cached)"
			ev.Result = model.SUCCESS_AUTH
			ev.RetCode = 200
			if auth_cache != nil {
				auth_cache.Add(ev.Username, hmac_b, cache.DefaultExpiration)
			}
		} else {
			if errwrap.ContainsType(err, new(auth.LdapOpError)) {
				ev.Message = fmt.Sprintf("LDAP operational error: %s", err.Error())
				ev.Result = model.OP_ERROR
				ev.RetCode = 500
			} else if errwrap.ContainsType(err, new(auth.LdapAuthError)) {
				ev.Message = "Auth failed"
				ev.Result = model.FAIL_AUTH
				ev.RetCode = 401
				if config.Http.FailedAuthDelay > 0 {
					// in auth context it is good practice to add a bit of random to counter time based attacks
					n, err := rand.Int(rand.Reader, big.NewInt(1000))
					if err != nil {
						log.Log.WithError(err).Error("Error generating random number. Check your rand source.")
					} else {
						time.Sleep(time.Duration(n.Int64()) * time.Millisecond)
					}
					time.Sleep(time.Duration(config.Http.FailedAuthDelay) * time.Second)
				}
			} else {
				ev.Message = fmt.Sprintf("Unexpected error: %s", err.Error())
				ev.Result = model.OP_ERROR
				ev.RetCode = 500
			}
		}
	}

	mux.HandleFunc("/", main_handler)

	done := make(chan bool, 1)
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
				log.Log.WithError(err).Info("HTTP server error. (Probably normal)")
			case *net.OpError:
				log.Log.WithError(err).Error("HTTP server operational error")
			}
		}
		done <- true
		close(done)
	}()

	return server, done
}
