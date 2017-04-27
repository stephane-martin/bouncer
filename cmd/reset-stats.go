package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	"github.com/stephane-martin/nginx-auth-ldap/model"
	"github.com/stephane-martin/nginx-auth-ldap/stats"
)

// reset-statsCmd represents the reset-stats command
var resetstatsCmd = &cobra.Command{
	Use:   "reset-stats",
	Short: "Reset statistics",
	Long:  `reset-stats erases the metrics that were persisted in Redis.`,
	Run: func(cmd *cobra.Command, args []string) {

		config, err := conf.Load(ConfigDir)
		if err != nil {
			log.Log.WithError(err).Error("Error loading configuration")
			os.Exit(-1)
		}

		if !config.Redis.Enabled {
			log.Log.Info("Redis not enabled")
			os.Exit(0)
		}

		err = config.CheckRedisConn()
		if err != nil {
			log.Log.WithError(err).Error("Connection to Redis failed.")
			os.Exit(-1)
		}

		client := config.GetRedisClient()
		pipe := client.TxPipeline()
		pipe.Del(stats.TOTAL_REQUESTS)
		for _, t := range model.ResultTypes {
			pipe.Del(fmt.Sprintf(stats.SET_REQUESTS_TPL, t))
		}
		for _, name := range model.CounterNames {
			pipe.Del(fmt.Sprintf(stats.COUNTER_TPL, name))
		}
		_, err = pipe.Exec()
		if err == nil {
			log.Log.Info("Stats have been erased in Redis.")
		} else {
			log.Log.WithError(err).Error("Error executing erasements in Redis.")
		}

	},
}

func init() {
	RootCmd.AddCommand(resetstatsCmd)
}
