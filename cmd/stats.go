// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	"github.com/stephane-martin/nginx-auth-ldap/stats"
)

var period uint64

// statsCmd represents the stats command
var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Display the metrics",
	Long:  `Gather information from Redis and print metrics to stdout.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, _, err := conf.Load(ConfigDir, ConsulAddr, ConsulPrefix, ConsulToken, ConsulDatacenter, nil)
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

		all_ranges := map[string]int64{
			"last_day":  86400,
			"last_hour": 3600,
			"last_min":  60,
		}

		if period > 0 {
			period_name := fmt.Sprintf("last_%d_seconds", period)
			all_ranges = map[string]int64{period_name: int64(period)}	
		}

		client := config.GetRedisClient()
		mngr := stats.NewStatsManager(client)
		measures, err := mngr.GetStats(all_ranges)
		if err != nil {
			log.Log.WithError(err).Error("Error getting stats from Redis")
			os.Exit(-1)
		}
		out, err := measures.Json()
		if err != nil {
			log.Log.WithError(err).Error("Error marshalling stats")
			os.Exit(-1)
		}
		fmt.Println(string(out))

	},
}

func init() {
	RootCmd.AddCommand(statsCmd)
	statsCmd.Flags().Uint64Var(&period, "period", 0, "display stats for this number of seconds")
}
