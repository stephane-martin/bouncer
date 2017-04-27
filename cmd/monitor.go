package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
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

var back_period uint64

func init() {
	RootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().Uint64Var(&back_period, "back", 60, "Print the requests that happened in the last number of seconds")
}

func monitor() {
	config, err := conf.Load(ConfigDir)
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

	if back_period > 0 {

	}
	pubsub := client.Subscribe(stats.NOTIFICATIONS_REDIS_CHAN)
	defer pubsub.Close()
	msg_chan := pubsub.Channel()

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
				fmt.Println(msg.Payload)
			} else {
				restart = false
			}
		}
	}

}
