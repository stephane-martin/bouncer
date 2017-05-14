package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephane-martin/bouncer/conf"
	"github.com/stephane-martin/bouncer/log"
	"github.com/stephane-martin/bouncer/model"
	"github.com/stephane-martin/bouncer/stats"
)

// logsCmd represents the logs command
var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Print past requests logs",
	Run: func(cmd *cobra.Command, args []string) {
		logs()
	},
}

var logs_from string
var logs_to string
var fuzzy bool

func init() {
	RootCmd.AddCommand(logsCmd)
	//logsCmd.Flags().BoolVar(&fuzzy, "fuzzy", false, "If true, consider that --from and --to are fuzzy times. If false, RFC3339.")
	logsCmd.Flags().StringVar(&logs_from, "from", "", "Get logs from that date/time")
	logsCmd.Flags().StringVar(&logs_to, "to", "", "Get logs until that date/time")
}

func logs() {
	var from time.Time
	var to time.Time
	var err error
	logs_from = strings.TrimSpace(logs_from)
	logs_to = strings.TrimSpace(logs_to)

	if len(logs_from) == 0 {
		from = time.Unix(0, 0)
	} else {
		from, err = time.Parse(time.RFC3339, logs_from)
		if err != nil {
			log.Log.WithError(err).Error("Failed to parse --from")
			os.Exit(-1)
		}
	}

	if len(logs_to) == 0 {
		to = time.Now().Add(time.Duration(86400) * time.Second)
	} else {
		to, err = time.Parse(time.RFC3339, logs_to)
		if err != nil {
			log.Log.WithError(err).Error("Failed to parse --to")
			os.Exit(-1)
		}
	}

	config, _, err := conf.Load(ConfigDir, ConsulAddr, ConsulPrefix, ConsulToken, ConsulDatacenter, nil)
	if err != nil {
		log.Log.WithError(err).Error("Error loading configuration")
		os.Exit(-1)
	}

	if !config.Redis.Enabled {
		log.Log.Info("Redis not enabled")
		os.Exit(0)
	}

	client := config.GetRedisClient()
	mngr := stats.NewManager(client)
	defer mngr.Close()

	packs, err := mngr.GetLogs(from, to)
	if err != nil {
		log.Log.WithError(err).Error("Error getting logs from Redis")
		os.Exit(-1)
	}
	events := model.PackOfEvents{}
	for _, t := range model.ResultTypes {
		pack := *(packs[t])
		events = append(events, pack...)
	}
	sort.Sort(events)
	for _, ev := range events {
		if LogInJSON {
			b, err := json.Marshal(*ev)
			if err == nil {
				fmt.Println(string(b))
			}
		} else {
			fmt.Println(ev)
		}
	}
}
