package cmd

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

var one_minute int64 = 60000000000
var one_hour int64 = 3600000000000
var one_day int64 = 86400000000000

type Result uint8

const (
	SUCCESS_AUTH Result = iota
	SUCCESS_AUTH_CACHE
	FAIL_AUTH
	INVALID_REQUEST
	OP_ERROR
)

const TOTAL_REQUESTS = "nginx-auth-ldap-nb-total-requests"



type Measurement struct {
	Period string `json:"period"`
	Success int64 `json:"success"`
	CachedSuccess int64 `json:"cache_success"`
	Fail int64 `json:"fail"`
	Invalid int64 `json:"invalid"`
	OpError int64 `json:"op_error"`
}

type TotalMeasurement struct {
	NbRequests int64 `json:"total_nb_requests"`
}

type Event struct {
	Username  string `json:"username"`
	Password  string `json:"-"`
	Uri       string `json:"uri"`
	RetCode   int    `json:"retcode"`
	Timestamp int64  `json:"timestamp,string"`
	Message   string `json:"message"`
	Result    Result `json:"result"`
}

func (e *Event) hmac(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(e.Username))
	mac.Write([]byte(":"))
	mac.Write([]byte(e.Password))
	return mac.Sum(nil)
}

func (e *Event) log() {
	l := log.Log.WithField("username", e.Username).WithField("uri", e.Uri).WithField("retcode", e.RetCode).WithField("result", e.Result)
	if e.RetCode == 200 {
		l.Debug(e.Message)
	} else if e.RetCode == 500 {
		l.Warn(e.Message)
	} else {
		l.Info(e.Message)
	}
}

func (e *Event) write(w http.ResponseWriter, config *conf.GlobalConfig) {
	if e.RetCode == 401 {
		w.Header().Add(config.Http.AuthenticateHeader, fmt.Sprintf("Basic realm=\"%s\"", config.Http.Realm))
	}
	w.WriteHeader(e.RetCode)
}

func (e *Event) notify() {
	if e.RetCode == 500 {
		// signal myself that an unexpected problem happened
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGHUP)
	}
}

func (e *Event) store(client *redis.Client) {
	set := fmt.Sprintf("nginx-auth-ldap-sset-%d", e.Result)
	score := float64(e.Timestamp)
	value, err := json.Marshal(*e)
	if err == nil {
		pipe := client.TxPipeline()
		pipe.ZAdd(set, redis.Z{Score: score, Member: value})
		pipe.Incr(TOTAL_REQUESTS)
		_, err = pipe.Exec()
		if err != nil {
			log.Log.WithError(err).Error("Error writing an event to Redis")
		}
	} else {
		log.Log.WithError(err).Error("Error marshalling an event to JSON (should not happen!!!)")
	}

}

func init() {
	RootCmd.AddCommand(serveCmd)
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
		config, err := conf.Load(ConfigDir)
		if err != nil {
			log.Log.WithError(err).Error("Error loading configuration. Sleeping a while and restarting.")
			time.Sleep(time.Duration(30) * time.Second)
			break
		}

		err = auth.CheckLdapConn(config)
		if err != nil {
			log.Log.WithError(err).Error("Connection to LDAP failed. Sleeping a while and restarting.")
			time.Sleep(time.Duration(30) * time.Second)
			break
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
				jan = janitor.NewJanitor(config, redis_client, int(OP_ERROR))
				jan.Start()
			}
		}

		// install signal handlers
		sig_chan := make(chan os.Signal, 1)
		signal.Notify(sig_chan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

		server, done := StartHttp(config, redis_client)
		select {
		// wait for either a signal, or that the HTTP server stops
		case <-done:
			// stop signal handlers
			signal.Stop(sig_chan)
			close(sig_chan)
			log.Log.Error("Abrupt termination of the HTTP server. Sleeping a while and restarting.")
			time.Sleep(time.Duration(30) * time.Second)

		case sig := <-sig_chan:
			// stop signal handlers... in both cases
			signal.Stop(sig_chan)
			close(sig_chan)

			var ctx context.Context
			var cancel_ctx context.CancelFunc
			if config.Http.ShutdownTimeout > 0 {
				ctx, cancel_ctx = context.WithTimeout(context.Background(), time.Duration(config.Http.ShutdownTimeout)*time.Second)
			}

			switch sig {
			case syscall.SIGTERM:
				log.Log.Info("SIGTERM received: stopping the HTTP server")
				server.Shutdown(ctx)
				<-done
				restart = false
			case syscall.SIGINT:
				log.Log.Info("SIGINT received: stopping the HTTP server")
				server.Shutdown(ctx)
				<-done
				restart = false
			case syscall.SIGHUP:
				log.Log.Info("SIGHUP received: reloading configuration and restart the HTTP server")
				server.Shutdown(ctx)
				<-done
			default:
				server.Shutdown(ctx)
				<-done
				restart = false
			}
			if config.Http.ShutdownTimeout > 0 {
				cancel_ctx()
			}
		}
		close(done)
		if config.Redis.Enabled {
			jan.Stop()
		}
	}
}

func NewEvent(r *http.Request, config *conf.GlobalConfig) (e *Event) {
	e = &Event{Timestamp: time.Now().UnixNano()}
	authorization := strings.TrimSpace(r.Header.Get(config.Http.AuthorizationHeader))
	e.Uri = strings.TrimSpace(r.Header.Get(config.Http.OriginalUriHeader))

	if len(authorization) == 0 {
		e.RetCode = 401
		e.Result = INVALID_REQUEST
		e.Message = "No Authorization header in request"
		return e
	}
	splits := strings.Split(authorization, " ")
	if len(splits) != 2 {
		e.RetCode = 400
		e.Result = INVALID_REQUEST
		e.Message = "Authorization header is present but has a bad format"
		return e
	}
	if splits[0] != "Basic" {
		e.RetCode = 400
		e.Result = INVALID_REQUEST
		e.Message = "Authorization header is present but does not begin with 'Basic'"
		return e
	}
	encoded := splits[1]
	if len(encoded) == 0 {
		e.RetCode = 400
		e.Result = INVALID_REQUEST
		e.Message = "The encoded base64 is empty"
		return e
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		e.RetCode = 400
		e.Result = INVALID_REQUEST
		e.Message = "Not properly base64 encoded"
		return e
	}
	splits = strings.Split(string(decoded), ":")
	if len(splits) != 2 {
		e.RetCode = 400
		e.Result = INVALID_REQUEST
		e.Message = "The decoded base64 does not contain a ':'"
		return e
	}
	e.Username = strings.TrimSpace(splits[0])
	e.Password = strings.TrimSpace(splits[1])
	if len(e.Username) == 0 || len(e.Password) == 0 {
		e.RetCode = 401
		e.Result = FAIL_AUTH
		e.Message = "Empty username or empty password"
		return e
	}
	return e
}

func StartHttp(config *conf.GlobalConfig, redis_client *redis.Client) (*http.Server, chan bool) {

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

		ev := NewEvent(r, config)
		defer ev.notify()
		defer ev.log()
		defer ev.write(w, config)
		if config.Redis.Enabled {
			defer ev.store(redis_client)
		}

		if ev.RetCode != 0 {
			return
		}

		if auth_cache != nil {
			hmac_b = ev.hmac(secret)
			cached_hmac_b, found := auth_cache.Get(ev.Username)
			if found {
				if hmac.Equal(hmac_b, cached_hmac_b.([]byte)) {
					ev.Message = "Auth is successful (cached)"
					ev.Result = SUCCESS_AUTH_CACHE
					ev.RetCode = 200
					return
				}
			}
		}

		err := auth.Authenticate(ev.Username, ev.Password, config)
		if err == nil {
			ev.Message = "Auth is succesful (not cached)"
			ev.Result = SUCCESS_AUTH
			ev.RetCode = 200
			if auth_cache != nil {
				auth_cache.Add(ev.Username, hmac_b, cache.DefaultExpiration)
			}
		} else {
			if errwrap.ContainsType(err, new(auth.LdapOpError)) {
				ev.Message = fmt.Sprintf("LDAP operational error: %s", err.Error())
				ev.Result = OP_ERROR
				ev.RetCode = 500
			} else if errwrap.ContainsType(err, new(auth.LdapAuthError)) {
				ev.Message = "Auth failed"
				ev.Result = FAIL_AUTH
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
				ev.Result = OP_ERROR
				ev.RetCode = 500
			}
		}
	}

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
			p, _ := os.FindProcess(os.Getpid())
			p.Signal(syscall.SIGHUP)
		} else {
			// we're alive
			w.WriteHeader(200)
		}
	}

	stats_handler := func(w http.ResponseWriter, r *http.Request) {
		// report statistics
		now := time.Now().UnixNano()
		now_s := strconv.FormatInt(now, 10)
		one_minute_ago := strconv.FormatInt(now-one_minute, 10)
		one_hour_ago := strconv.FormatInt(now-one_hour, 10)
		one_day_ago := strconv.FormatInt(now-one_day, 10)

		range_minute := redis.ZRangeBy{Min: one_minute_ago, Max: now_s}
		range_hour := redis.ZRangeBy{Min: one_hour_ago, Max: now_s}
		range_day := redis.ZRangeBy{Min: one_day_ago, Max: now_s}

		all_ranges := map[string]redis.ZRangeBy{
			"minute": range_minute,
			"hour":   range_hour,
			"day":    range_day,
		}

		measurements := []interface{}{}
		for period, one_range := range all_ranges {
			measurement := Measurement{Period: period}

			sset := fmt.Sprintf("nginx-auth-ldap-sset-%d", SUCCESS_AUTH)
			result, err := redis_client.ZCount(sset, one_range.Min, one_range.Max).Result()
			if err != nil {
				w.WriteHeader(500)
				log.Log.WithError(err).Error("Error querying history in Redis")
				return
			}
			measurement.Success = result

			sset = fmt.Sprintf("nginx-auth-ldap-sset-%d", SUCCESS_AUTH_CACHE)
			result, err = redis_client.ZCount(sset, one_range.Min, one_range.Max).Result()
			if err != nil {
				w.WriteHeader(500)
				log.Log.WithError(err).Error("Error querying history in Redis")
				return
			}
			measurement.CachedSuccess = result	
		
			sset = fmt.Sprintf("nginx-auth-ldap-sset-%d", FAIL_AUTH)
			result, err = redis_client.ZCount(sset, one_range.Min, one_range.Max).Result()
			if err != nil {
				w.WriteHeader(500)
				log.Log.WithError(err).Error("Error querying history in Redis")
				return
			}
			measurement.Fail = result	

			sset = fmt.Sprintf("nginx-auth-ldap-sset-%d", INVALID_REQUEST)
			result, err = redis_client.ZCount(sset, one_range.Min, one_range.Max).Result()
			if err != nil {
				w.WriteHeader(500)
				log.Log.WithError(err).Error("Error querying history in Redis")
				return
			}
			measurement.Invalid = result	

			sset = fmt.Sprintf("nginx-auth-ldap-sset-%d", OP_ERROR)
			result, err = redis_client.ZCount(sset, one_range.Min, one_range.Max).Result()
			if err != nil {
				log.Log.WithError(err).Error("Error querying history in Redis")
				w.WriteHeader(500)
				return
			}
			measurement.OpError = result
			measurements = append(measurements, measurement)

		}

		total_s, err := redis_client.Get(TOTAL_REQUESTS).Result()
		if err != nil {
			log.Log.WithError(err).Error("Error querying the total number of requests in Redis")
			w.WriteHeader(500)
			return
		}
		total, err := strconv.ParseInt(total_s, 10, 64)
		if err != nil {
			log.Log.WithError(err).Error("The total number of requests in Redis is not an Int ??!")
			w.WriteHeader(500)
			return
		}
		measurements = append(measurements, TotalMeasurement{total})

		measurements_b, err := json.Marshal(measurements)
		if err != nil {
			log.Log.WithError(err).Error("Error marshalling statistics to JSON")
			w.WriteHeader(500)
		} else {
			w.WriteHeader(200)
			w.Header().Set("Content-Type", "application/json")
			w.Write(measurements_b)
		}
	}

	mux.HandleFunc("/", main_handler)
	mux.HandleFunc("/status", status_handler)
	mux.HandleFunc("/check", check_handler)
	if config.Redis.Enabled {
		mux.HandleFunc("/stats", stats_handler)
	}

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
	}()

	return server, done
}
