package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/go-redis/redis"
	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	"github.com/stephane-martin/nginx-auth-ldap/model"
	"github.com/stephane-martin/nginx-auth-ldap/stats"
)

// monitorCmd represents the monitor command
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Watch the stream of requests",
	Long: `monitor displays the logs of recent requests and prints new requests
as they come.`,
	Run: func(cmd *cobra.Command, args []string) {
		monitor()
	},
}

var back_period int64

func init() {
	RootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().Int64Var(&back_period, "back", 0, "Also print the requests that happened in the last number of seconds")
}

func monitor() {
	config, _, err := conf.Load(ConfigDir, ConsulAddr, ConsulPrefix, ConsulToken, ConsulDatacenter, nil)
	if err != nil {
		log.Log.WithError(err).Error("Error loading configuration")
		os.Exit(-1)
	}

	if !config.Redis.Enabled {
		log.Log.Info("Redis not enabled")
		os.Exit(0)
	}

	// prevent SIGHUP to stop the program in all cases
	signal.Ignore(syscall.SIGHUP)

	err = config.CheckRedisConn()
	if err != nil {
		log.Log.WithError(err).Error("Connection to Redis failed.")
		os.Exit(-1)
	}

	client := config.GetRedisClient()
	now := time.Now().UnixNano()
	pubsub := client.Subscribe(stats.NOTIFICATIONS_REDIS_CHAN)
	defer pubsub.Close()
	msg_chan := pubsub.Channel()

	if back_period > 0 {
		from := now - (back_period * 1000000000)
		r := redis.ZRangeBy{Min: strconv.FormatInt(from, 10), Max: strconv.FormatInt(now, 10)}
		pipe := client.TxPipeline()
		cmds := []*redis.StringSliceCmd{}
		for _, t := range model.ResultTypes {
			sset := fmt.Sprintf(stats.SET_REQUESTS_TPL, t)
			cmds = append(cmds, pipe.ZRangeByScore(sset, r))
		}
		_, err := pipe.Exec()
		if err != nil {
			log.Log.WithError(err).Error("Error getting logs from Redis")
			os.Exit(-1)
		}
		events := model.PackOfEvents{}
		for _, cmd := range cmds {
			for _, event_s := range cmd.Val() {
				ev := model.RequestEvent{}
				err := json.Unmarshal([]byte(event_s), &ev)
				if err == nil {
					events = append(events, &ev)
				} else {
					log.Log.WithError(err).WithField("event", event_s).Warn("Error decoding an event from Redis")
				}
			}
		}
		sort.Sort(events)
		for _, ev := range events {
			if Json {
				b, err := json.Marshal(*ev)
				if err == nil {
					fmt.Println(string(b))
				}
			} else {
				fmt.Println(ev)
			}
		}
	}

	// install signal handlers
	sig_chan := make(chan os.Signal, 1)
	signal.Notify(sig_chan, syscall.SIGTERM, syscall.SIGINT)

	restart := true

	for restart {
		select {
		case <-sig_chan:
			signal.Stop(sig_chan)
			close(sig_chan)
			restart = false
		case msg, more := <-msg_chan:
			if more {
				ev := model.RequestEvent{}
				err := json.Unmarshal([]byte(msg.Payload), &ev)
				if err != nil {
					log.Log.WithError(err).WithField("event", msg.Payload).Warn("Error decoding an event from Redis")
				} else if Json {
					fmt.Println(msg.Payload)
				} else {
					fmt.Println(&ev)
				}
			} else {
				restart = false
			}
		}
	}

}
