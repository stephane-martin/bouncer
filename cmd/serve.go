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
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/facebookgo/pidfile"
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

func sigusr() {
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(syscall.SIGUSR1)
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

	// prevent SIGHUP and SIGURS1 to stop the program in all cases
	signal.Ignore(syscall.SIGHUP)
	signal.Ignore(syscall.SIGUSR1)

	restart := true
	for restart {
		restart = do_serve()
	}
}

func do_serve() bool {
	var notify_updated_conf chan bool
	var stop_chan chan bool
	var err error
	var config *conf.GlobalConfig
	var discovery *conf.DiscoveryLdap

	if len(ConsulAddr) > 0 {
		// read configuration from Consul and be notified of configuration updates
		notify_updated_conf = make(chan bool, 100) // todo: size?
		// conf.Load is responsible to close notify_updated_conf in all cases
		// we can use stop_chan to say that we are not interested in notifications anymore
		config, stop_chan, err = conf.Load(ConfigDir, ConsulAddr, ConsulPrefix, ConsulToken, ConsulDatacenter, notify_updated_conf)
	} else {
		notify_updated_conf = make(chan bool, 1) // dummy, won't receive anything
		defer close(notify_updated_conf)
		config, _, err = conf.Load(ConfigDir, "", "", "", "", nil)
	}

	if err != nil {
		log.Log.WithError(err).Error("Error loading configuration. Sleeping a while and restarting.")
		time.Sleep(time.Duration(30) * time.Second)
		return true
	}

	if stop_chan != nil {
		defer close(stop_chan)
	}

	if len(ConsulAddr) > 0 && len(ConsulLdapServiceName) > 0 {
		// discover LDAP servers through Consul health checks
		discovery, err = conf.NewDiscoveryLdap(config, ConsulAddr, ConsulToken, ConsulLdapDatacenter, ConsulLdapTag, ConsulLdapServiceName)
		if err != nil {
			log.Log.WithError(err).Error("Error initializing LDAP discovery. Discovery is disabled.")
			discovery = nil
		} else {
			discovery.Watch()
			defer discovery.StopWatch()
		}
	}

	mngr := stats.NewStatsManager(nil)
	defer mngr.Close()

	if config.Redis.Enabled {
		err = config.CheckRedisConn()
		if err != nil {
			log.Log.WithError(err).Error("Connection to Redis failed. Stats won't be available.")
			config.Redis.Enabled = false
		} else {
			mngr.Client = config.GetRedisClient()
			if config.Redis.Expires > 0 {
				j := janitor.NewJanitor(config, mngr.Client)
				j.Start()
				defer j.Stop()
			}
		}
	}

	for i, _ := range model.CounterNames {
		mngr.RegCounter(i)
	}

	mngr.Counter(model.RESTARTS).Incr()

	err = auth.CheckLdapConn(config, discovery)
	if err != nil {
		log.Log.WithError(err).Error("Connection to LDAP failed. Sleeping a while and restarting.")
		mngr.Counter(model.LDAP_CONN_ERROR).Incr()
		time.Sleep(time.Duration(30) * time.Second)
		return true
	}

	// install signal handlers
	sig_chan := make(chan os.Signal, 1)
	signal.Notify(sig_chan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1)

	ctx := context.Background()
	api_ctx, cancel_api_ctx := context.WithTimeout(context.Background(), time.Duration(time.Second))
	defer cancel_api_ctx()
	var cancel_ctx context.CancelFunc
	if config.Http.ShutdownTimeout > 0 {
		ctx, cancel_ctx = context.WithTimeout(context.Background(), time.Duration(config.Http.ShutdownTimeout)*time.Second)
		defer cancel_ctx()
	}

	server, done := StartHttp(config, discovery, mngr)
	api, api_done := StartApi(config, discovery, mngr)

	select {
	// wait for either a signal, or that the HTTP server stops
	case <-done:
		// stop signal handlers
		signal.Stop(sig_chan)
		close(sig_chan)
		log.Log.Error("Abrupt termination of the HTTP server. Sleeping a while and restarting.")
		api.Shutdown(api_ctx)
		<-api_done
		mngr.Counter(model.HTTP_ABRUPT_TERM).Incr()
		time.Sleep(time.Duration(30) * time.Second)
		return true

	case <-api_done:
		signal.Stop(sig_chan)
		close(sig_chan)
		log.Log.Error("Abrupt termination of the API server. Sleeping a while and restarting.")
		server.Shutdown(ctx)
		<-done
		mngr.Counter(model.API_ABRUPT_TERM).Incr()
		time.Sleep(time.Duration(30) * time.Second)
		return true

	case <-notify_updated_conf:
		signal.Stop(sig_chan)
		close(sig_chan)
		log.Log.Info("New configuration was notified by Consul: restarting")
		server.Shutdown(ctx)
		api.Shutdown(api_ctx)
		<-done
		<-api_done
		return true

	case sig := <-sig_chan:
		// stop signal handlers... in all cases
		signal.Stop(sig_chan)
		close(sig_chan)

		switch sig {
		case syscall.SIGTERM, syscall.SIGINT:
			log.Log.Info("SIGTERM received: stopping the HTTP servers")
			server.Shutdown(ctx)
			api.Shutdown(api_ctx)
			<-done
			<-api_done
			mngr.Counter(model.SIGTERM_SIGINT).Incr()
			return false
		case syscall.SIGHUP:
			log.Log.Info("SIGHUP received: reloading configuration and restart the HTTP servers")
			server.Shutdown(ctx)
			api.Shutdown(api_ctx)
			<-done
			<-api_done
			mngr.Counter(model.SIGHUP).Incr()
			return true
		case syscall.SIGUSR1:
			log.Log.Info("SIGUSR1 received: unable to work. Sleeping then restarting.")
			server.Shutdown(ctx)
			api.Shutdown(api_ctx)
			<-done
			<-api_done
			time.Sleep(time.Duration(30) * time.Second)
			return true
		default:
			server.Shutdown(ctx)
			api.Shutdown(api_ctx)
			<-done
			<-api_done
			mngr.Counter(model.UNKNOWN_SIG).Incr()
			return false
		}
	}
}

func EventFromRequest(r *http.Request, config *conf.GlobalConfig) (e *model.Event) {
	e = model.NewEmptyEvent()
	e.Username = strings.TrimSpace(r.FormValue("username"))
	e.Password = strings.TrimSpace(r.FormValue("password"))

	uri := strings.TrimSpace(r.FormValue("uri"))
	if len(uri) > 0 {
		parsed_uri, err := url.Parse(uri)
		if err != nil {
			e.RetCode = 400
			e.Result = model.INVALID_REQUEST
			e.Message = "The passed URI could not be parsed"
			return e
		}
		e.Host = parsed_uri.Hostname()
		e.Port = parsed_uri.Port()
		e.Uri = parsed_uri.RequestURI()
		e.Proto = parsed_uri.Scheme
	} else {
		e.Host = ""
		e.Uri = ""
		e.Port = ""
		e.Proto = ""
	}

	if len(e.Username) == 0 || len(e.Password) == 0 {
		e.RetCode = 403
		e.Result = model.FAIL_AUTH
		e.Message = "Empty username or empty password"
		return e
	}

	return e
}

func EventFromSubRequest(r *http.Request, config *conf.GlobalConfig) (e *model.Event) {
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
		e.RetCode = 403
		e.Result = model.FAIL_AUTH
		e.Message = "Empty username or empty password"
		return e
	}
	return e
}

func StartApi(config *conf.GlobalConfig, discovery *conf.DiscoveryLdap, mngr *stats.StatsManager) (*http.Server, chan bool) {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.Api.BindAddr, config.Api.Port),
		Handler: mux,
	}

	status_handler := func(w http.ResponseWriter, r *http.Request) {
		// just reply that the server is alive
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><head><title>nginx-auth-ldap</title></head><body><h1>nginx-auth-ldap is running</h1></body></html>"))
		return
	}

	check_handler := func(w http.ResponseWriter, r *http.Request) {
		err := auth.CheckLdapConn(config, discovery)
		if err != nil {
			// we have a connection problem to LDAP...
			log.Log.WithError(err).Error("Check LDAP connection failed")
			// first reply that the health check is negative
			w.WriteHeader(500)
			// then send signal to myself to stop the HTTP server
			sigusr()
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

	events_handler := func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}
		notify := w.(http.CloseNotifier).CloseNotify()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		pubsub := mngr.Client.Subscribe(stats.NOTIFICATIONS_REDIS_CHAN)
		defer pubsub.Close()
		msg_chan := pubsub.Channel()
		restart := true

		for restart {
			select {
			case <-notify:
				restart = false
			case msg, more := <-msg_chan:
				if more {
					fmt.Fprintf(w, "data: %s\n\n", msg.Payload)
					f.Flush()
				} else {
					restart = false
				}
			}
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

		measurements, err := mngr.GetStats(all_ranges)
		if err != nil {
			log.Log.WithError(err).WithField("errtype", fmt.Sprintf("%T", err)).Error("Error querying stats in Redis")
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
	mux.HandleFunc("/reload", reload_handler)

	if config.Redis.Enabled {
		mux.HandleFunc("/stats", stats_handler)
		mux.HandleFunc("/events", events_handler)
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
		close(done)
	}()

	return server, done

}

func StartHttp(config *conf.GlobalConfig, discovery *conf.DiscoveryLdap, mngr *stats.StatsManager) (*http.Server, chan bool) {

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.Http.BindAddr, config.Http.Port),
		Handler: mux,
	}

	var secret []byte
	var err error
	var auth_cache *cache.Cache
	event_chan := make(chan *model.Event, 100)

	if config.Cache.Expires > 0 {
		expires := time.Duration(config.Cache.Expires) * time.Second
		auth_cache = cache.New(expires, 10*expires)
		secret, err = config.GenerateSecret()
		if err != nil {
			log.Log.WithError(err).Error("Error generating secret!!!")
			os.Exit(-1)
		}
	}

	event_handler := func(w http.ResponseWriter, ev *model.Event) {
		var hmac_b []byte

		// make sure we post an answer
		defer func() {
			if ev.RetCode == 401 {
				w.Header().Add(config.Http.AuthenticateHeader, fmt.Sprintf("Basic realm=\"%s\"", config.Http.Realm))
			}
			w.WriteHeader(ev.RetCode)
			// perform post-processing in a separate goroutine
			event_chan <- ev
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

		// todo: measure auth time
		err := auth.Authenticate(ev.Username, ev.Password, config, discovery)

		if err == nil {
			ev.Message = "Auth is succesful (not cached)"
			ev.Result = model.SUCCESS_AUTH
			ev.RetCode = 200
			if auth_cache != nil {
				auth_cache.Add(ev.Username, hmac_b, cache.DefaultExpiration)
			}
			return
		}

		if errwrap.ContainsType(err, new(auth.LdapOpError)) {
			ev.Message = fmt.Sprintf("LDAP operational error: %s", err.Error())
			ev.Result = model.OP_ERROR
			ev.RetCode = 500
			return
		}

		if errwrap.ContainsType(err, new(auth.LdapAuthError)) {
			ev.Message = fmt.Sprintf("Auth failed: %s", err.Error())
			ev.Result = model.FAIL_AUTH
			ev.RetCode = 403
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
			return
		}

		if errwrap.ContainsType(err, new(auth.NoLdapServer)) {
			ev.Message = err.Error()
			ev.Result = model.OP_ERROR
			ev.RetCode = 500
			return
		}

		ev.Message = fmt.Sprintf("Unexpected error: %s", err.Error())
		ev.Result = model.OP_ERROR
		ev.RetCode = 500
	}

	nginx_subrequest_handler := func(w http.ResponseWriter, r *http.Request) {
		ev := EventFromSubRequest(r, config)
		event_handler(w, ev)
	}

	direct_auth_handler := func (w http.ResponseWriter, r *http.Request) {
		ev := EventFromRequest(r, config)
		event_handler(w, ev)
	}

	mux.HandleFunc("/nginx", nginx_subrequest_handler)
	mux.HandleFunc("/auth", direct_auth_handler)

	go func() {
		// postprocessing events
		for ev := range event_chan {
			// log the event
			l := log.Log.WithField("username", ev.Username).WithField("uri", ev.Uri).WithField("retcode", ev.RetCode).WithField("result", ev.Result)
			if ev.RetCode == 200 {
				l.Debug(ev.Message)
			} else if ev.RetCode == 500 {
				l.Warn(ev.Message)
			} else {
				l.Info(ev.Message)
			}
			// write it to Redis
			if config.Redis.Enabled {
				err := mngr.Store(ev)
				if err != nil {
					log.Log.WithError(err).Error("Error happened when storing a request in Redis")
				}
			}
			// restart and wait if there was an operational error
			if ev.RetCode == 500 {
				sigusr()
			}
		}
	}()

	done := make(chan bool, 1)
	go func() {
		log.Log.WithField("bind", server.Addr).Info("Starting HTTP server")
		var err error
		if config.Http.Https {
			err = server.ListenAndServeTLS(config.Http.Certificate, config.Http.Key)
		} else {
			err = server.ListenAndServe()
		}

		close(event_chan)
		close(done)

		if err != nil {
			switch err := err.(type) {
			default:
				log.Log.WithError(err).Info("HTTP server error. (Probably normal)")
			case *net.OpError:
				log.Log.WithError(err).Error("HTTP server operational error")
			}
		}

	}()

	return server, done
}
