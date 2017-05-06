package cmd

import (
	"context"
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
	//cache "github.com/patrickmn/go-cache"
	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/auth"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/consul"
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

var register_in_consul bool
var api_service_name string
var auth_service_name string
var api_tags string
var self_tags string

func init() {
	RootCmd.AddCommand(serveCmd)
	serveCmd.Flags().BoolVar(&register_in_consul, "register", false, "Register nginx-auth-ldap services in Consul")
	serveCmd.Flags().StringVar(&auth_service_name, "service-name", "nginx-auth-ldap", "The Consul name to register for the Auth service")
	serveCmd.Flags().StringVar(&api_service_name, "api-service-name", "nginx-auth-ldap-api", "The Consul name to register for the API service")
	serveCmd.Flags().StringVar(&self_tags, "tags", "", "Comma-separated list of Consul tags to set for the Auth service")
	serveCmd.Flags().StringVar(&api_tags, "api-tags", "", "Comma-separated list of Consul tags to set for the API service")
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

	if Syslog || len(LogFilename) > 0 || len(RequestLogFilename) > 0 {
		// plaintext for syslog
		disable_timestamps = true
		disable_colors = true
	}

	if Json {
		// logs formatted as JSON
		log.Log.Formatter = &logrus.JSONFormatter{DisableTimestamp: disable_timestamps}
		log.RequestLog.Formatter = &logrus.JSONFormatter{DisableTimestamp: disable_timestamps}
	} else {
		log.Log.Formatter = &logrus.TextFormatter{DisableColors: disable_colors, DisableTimestamp: disable_timestamps, FullTimestamp: true}
		log.RequestLog.Formatter = &logrus.TextFormatter{DisableColors: disable_colors, DisableTimestamp: disable_timestamps, FullTimestamp: true}
	}

	if Syslog {
		hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, "nal")
		requests_hook, err2 := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, "nal-req")
		if err == nil && err2 == nil {
			log.Log.Hooks.Add(hook)
			log.RequestLog.Hooks.Add(requests_hook)
			// if we log to syslog, we don't log to stderr
			f, err := os.OpenFile("/dev/null", os.O_WRONLY, 0600)
			if err == nil {
				log.Log.Out = f
				log.RequestLog.Out = f
				defer f.Close()
			}
		} else {
			var e error
			if err != nil {
				e = err
			} else {
				e = err2
			}
			log.Log.WithError(e).Error("Unable to connect to local syslog daemon")
		}
	}

	if len(LogFilename) > 0 {
		// write the logs to a file
		f, err := os.OpenFile(LogFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
		if err != nil {
			log.Log.WithError(err).WithField("logfile", LogFilename).Fatal("Failed to open the log file")
		}
		defer f.Close()
		log.Log.Out = f
	}

	if len(RequestLogFilename) > 0 {
		// write the logs to a file
		f, err := os.OpenFile(RequestLogFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
		if err != nil {
			log.Log.WithError(err).WithField("req-logfile", RequestLogFilename).Fatal("Failed to open the log file")
		}
		defer f.Close()
		log.Log.Out = f
	}

	if len(PidFilename) > 0 {
		// write the current PID to a file
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
		// just read configuration from file and environment
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

	// statistics manager. Initialized with a nil redis client, it will do nothing.
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
				// the janitor removes old records from redis
				j := janitor.NewJanitor(config, mngr.Client)
				j.Start()
				defer j.Stop()
			}
		}
	}

	// initialize (Redis stored) counters
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
		// we set a timeout to stop the Auth service
		ctx, cancel_ctx = context.WithTimeout(context.Background(), time.Duration(config.Http.ShutdownTimeout)*time.Second)
		defer cancel_ctx()
	}

	server, done := StartHttp(config, discovery, mngr)
	api, api_done := StartApi(config, discovery, mngr)

	if register_in_consul && len(ConsulAddr) > 0 {
		// register the API service and the Auth service in Consul
		tag_list := strings.Split(self_tags, ",")
		ui_tag_list := strings.Split(api_tags, ",")
		registry, err := consul.NewRegistry(ConsulAddr, ConsulToken, ConsulDatacenter)
		if err != nil {
			log.Log.WithError(err).Error("Failed to build the Consul registry")
		} else {
			ui_service_id, err := registry.Register(api_service_name, config.Api.BindAddr, int(config.Api.Port), "", ui_tag_list)
			if err != nil {
				log.Log.WithError(err).Error("Failed to register the API service")
			} else {
				defer registry.Unregister(ui_service_id)
			}
			self_service_id, err := registry.Register(auth_service_name, config.Http.BindAddr, int(config.Http.Port), "", tag_list)
			if err != nil {
				log.Log.WithError(err).Error("Failed to register the auth service")
			} else {
defer registry.Unregister(self_service_id)
			}
		}
	}

	select {
	// wait for a signal, for the termination of the HTTP servers, or for a modified configuration notification
	case <-done:
		// the Auth service has stopped
		signal.Stop(sig_chan)
		close(sig_chan)
		log.Log.Error("Abrupt termination of the HTTP server. Sleeping a while and restarting.")
		api.Shutdown(api_ctx)
		<-api_done
		mngr.Counter(model.HTTP_ABRUPT_TERM).Incr()
		time.Sleep(time.Duration(30) * time.Second)
		return true

	case <-api_done:
		// the API service has stopped
		signal.Stop(sig_chan)
		close(sig_chan)
		log.Log.Error("Abrupt termination of the API server. Sleeping a while and restarting.")
		server.Shutdown(ctx)
		<-done
		mngr.Counter(model.API_ABRUPT_TERM).Incr()
		time.Sleep(time.Duration(30) * time.Second)
		return true

	case <-notify_updated_conf:
		// consul notifies a change of configuration
		signal.Stop(sig_chan)
		close(sig_chan)
		log.Log.Info("New configuration was notified by Consul: restarting")
		server.Shutdown(ctx)
		api.Shutdown(api_ctx)
		<-done
		<-api_done
		return true

	case sig := <-sig_chan:
		// we received a signal
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

func EventFromRequest(r *http.Request, config *conf.GlobalConfig) (e *model.RequestEvent) {
	e = model.NewEmptyEvent()
	e.Username = strings.TrimSpace(r.FormValue("username"))
	e.Password = strings.TrimSpace(r.FormValue("password"))

	e.Cookie = ""
	cookie, err := r.Cookie(config.Http.NalCookieName)
	if err == nil {
		e.Cookie = cookie.Value
	}

	e.ClientIP = strings.TrimSpace(r.Header.Get(config.Http.RealIPHeader))
	if len(e.ClientIP) == 0 {
		e.ClientIP = r.RemoteAddr
	}

	uri := strings.TrimSpace(r.FormValue("uri"))
	if len(uri) > 0 {
		parsed_uri, err := url.Parse(uri)
		if err != nil {
			e.RetCode = 400
			e.Result = model.INVALID_REQUEST
			e.Message = fmt.Sprintf("The passed URI could not be parsed: %s", uri)
			return e
		}
		e.Host = parsed_uri.Hostname()
		e.Port = parsed_uri.Port()
		e.Uri = parsed_uri.RequestURI()
		e.Proto = parsed_uri.Scheme
	}

	token := e.VerifyCookie(config.Cache.SecretAsBytes)

	if len(e.Username) == 0 {
		if token == nil {
			e.RetCode = 403
			e.Result = model.FAIL_AUTH
			e.Message = "Empty username"
			return e
		} else {
			e.Username = token.Username
			e.UsernameOut = token.UsernameOut
			e.Email = token.Email
			e.Password = token.Password
			e.RetCode = 200
			e.Message = "Auth is succesful (by NAL Cookie)"
			e.Result = model.SUCCESS_AUTH_NAL_COOKIE
			return e
		}
	}
	// at this point we know that Username is not empty
	if token != nil {
		if e.Username == token.Username {
			e.Username = token.Username
			e.UsernameOut = token.UsernameOut
			e.Password = token.Password
			e.Email = token.Email
			e.RetCode = 200
			e.Message = "Auth is succesful (by NAL Cookie)"
			e.Result = model.SUCCESS_AUTH_NAL_COOKIE
			return e
		}
	}
	// at this point,
	// - either token is nil, and we'll have to check the password with LDAP
	// - or token is provided, but the usernames are different: we have to check the new username/pass with LDAP also
	if len(e.Password) == 0 {
		e.RetCode = 403
		e.Result = model.FAIL_AUTH
		e.Message = "Empty password"
		return e
	}

	return e
}

func EventFromSubRequest(r *http.Request, config *conf.GlobalConfig) (e *model.RequestEvent) {
	e = model.NewEmptyEvent()
	authorization := strings.TrimSpace(r.Header.Get(config.Http.AuthorizationHeader))
	e.Host = strings.TrimSpace(r.Header.Get(config.Http.OriginalHostHeader))
	e.Uri = strings.TrimSpace(r.Header.Get(config.Http.OriginalUriHeader))
	e.Port = strings.TrimSpace(r.Header.Get(config.Http.OriginalPortHeader))
	e.Proto = strings.TrimSpace(r.Header.Get(config.Http.OriginalProtoHeader))

	e.Cookie = ""
	cookie, err := r.Cookie(config.Http.NalCookieName)
	if err == nil {
		e.Cookie = cookie.Value
	}

	e.ClientIP = strings.TrimSpace(r.Header.Get(config.Http.RealIPHeader))
	if len(e.ClientIP) == 0 {
		e.ClientIP = r.RemoteAddr
	}

	token := e.VerifyCookie(config.Cache.SecretAsBytes)

	if len(authorization) == 0 {
		if token == nil {
			e.RetCode = 401
			e.Result = model.NO_AUTH
			e.Message = "No authorization header, no NAL cookie in request"
		} else {
			e.RetCode = 200
			e.Result = model.SUCCESS_AUTH_NAL_COOKIE
			e.Message = "Auth is succesful (by NAL Cookie)"
			e.Username = token.Username
			e.UsernameOut = token.UsernameOut
			e.Email = token.Email
			e.Password = token.Password
		}
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

	if token != nil {
		if e.Username == token.Username {
			e.RetCode = 200
			e.Result = model.SUCCESS_AUTH_NAL_COOKIE
			e.Message = "Auth is succesful (by NAL Cookie)"
			e.Username = token.Username
			e.UsernameOut = token.UsernameOut
			e.Email = token.Email
			e.Password = token.Password
			return e
		}
	}
	if len(e.Username) == 0 {
		e.RetCode = 403
		e.Result = model.FAIL_AUTH
		e.Message = "Empty username"
		return e
	}
	if len(e.Password) == 0 {
		e.RetCode = 403
		e.Result = model.FAIL_AUTH
		e.Message = "Empty password"
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

	health_handler := func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/health", health_handler)
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

	//var auth_cache *cache.Cache
	request_event_chan := make(chan *model.RequestEvent, 100)

	_request_event_handler := func(w http.ResponseWriter, ev *model.RequestEvent) {

		// make sure we post an answer
		defer func() {

			if ev.RetCode == 401 {
				w.Header().Add(config.Http.AuthenticateHeader, fmt.Sprintf("Basic realm=\"%s\"", config.Http.Realm))
			}

			// perform post-processing in a separate goroutine
			request_event_chan <- ev

			if ev.RetCode == 403 && config.Http.FailedAuthDelay > 0 {
				// in auth context it is good practice to add a bit of random to counter time based attacks
				n, err := rand.Int(rand.Reader, big.NewInt(1000))
				if err != nil {
					log.Log.WithError(err).Error("Error generating random number. Check your rand source.")
				} else {
					// sleep for some random time < 1s
					time.Sleep(time.Duration(n.Int64()) * time.Millisecond)
				}
				// sleep (fixed time)
				time.Sleep(time.Duration(config.Http.FailedAuthDelay) * time.Second)
			}

			if ev.RetCode == 200 {
				// pass the authenticated user in the response headers
				w.Header().Add(config.Http.RemoteUserHeader, ev.UsernameOut)

				// pass the modified Authorization in the response headers
				var pass string
				if config.Http.MaskPassword {
					pass = "XXXXXXXX"
				} else {
					pass = ev.Password
				}
				basic := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", ev.UsernameOut, pass)))
				w.Header().Add("Authorization", fmt.Sprintf("Basic %s", basic))

				// return the "caching cookie" in the response headers
				if ev.Result == model.SUCCESS_AUTH_NAL_COOKIE {
					w.Header().Add(config.Http.NalCookieHeader, ev.Cookie)
				} else {
					nal_cookie, err := ev.GenerateCookie(config.Cache.SecretAsBytes, config.Cache.Expires)
					if err != nil {
						log.Log.WithError(err).Error("Error generating NAL Cookie")
					} else {
						w.Header().Add(config.Http.NalCookieHeader, nal_cookie)
					}
				}

				// pass a JWT token representing the authenticated user
				if config.Signature.PrivateKey != nil {
					token, err := ev.GenerateBackendJwt(config.Signature.PrivateKey, auth_service_name)
					if err != nil {
						log.Log.WithError(err).Error("Error generating the JWT token")
					} else {
						w.Header().Add(config.Http.JwtHeader, token)
					}
				}
			} else {
				w.Header().Add(config.Http.RemoteUserHeader, "")
				w.Header().Add(config.Http.NalCookieHeader, "")
			}

			w.WriteHeader(ev.RetCode)
		}()

		if ev.RetCode != 0 {
			return
		}

		/*
			if auth_cache != nil {
				// fix: the cache should contain the whole resulting event
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
		*/

		// todo: measure auth time
		username_out, email, err := auth.Authenticate(ev.Username, ev.Password, config, discovery)

		if err == nil {
			ev.UsernameOut = username_out
			ev.Email = email
			ev.Message = "Auth is succesful (not cached)"
			ev.Result = model.SUCCESS_AUTH
			ev.RetCode = 200
			//if auth_cache != nil {
			//	auth_cache.Add(ev.Username, hmac_b, cache.DefaultExpiration)
			//}
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
		_request_event_handler(w, ev)
	}

	direct_auth_handler := func(w http.ResponseWriter, r *http.Request) {
		ev := EventFromRequest(r, config)
		_request_event_handler(w, ev)
	}

	health_handler := func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/nginx", nginx_subrequest_handler)
	mux.HandleFunc("/auth", direct_auth_handler)
	mux.HandleFunc("/health", health_handler)

	go func() {
		// postprocessing request events: log the request, archive it in redis, restart server if operational error
		for ev := range request_event_chan {
			// log the event
			l := log.RequestLog.
				WithField("username", ev.Username).
				WithField("username_out", ev.UsernameOut).
				WithField("host", ev.Host).
				WithField("port", ev.Port).
				WithField("proto", ev.Proto).
				WithField("timestamp", ev.Timestamp.Format(time.RFC3339)).
				WithField("client_ip", ev.ClientIP).
				WithField("uri", ev.Uri).
				WithField("retcode", ev.RetCode).
				WithField("result", ev.Result)
			if ev.RetCode == 200 {
				l.Debug(ev.Message)
			} else if ev.RetCode == 500 {
				l.Warn(ev.Message)
			} else {
				l.Info(ev.Message)
			}
			// write it to Redis
			err := mngr.Store(ev)
			if err != nil {
				log.Log.WithError(err).Error("Error happened when storing a request in Redis")
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

		close(request_event_chan)
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
