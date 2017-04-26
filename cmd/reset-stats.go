package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// reset-statsCmd represents the reset-stats command
var resetstatsCmd = &cobra.Command{
	Use:   "reset-stats",
	Short: "Reset statistics",
	Long: `reset-stats erases the metrics that were persisted in Redis.`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Work your own magic here
		fmt.Println("reset-stats called")
	},
}

func init() {
	RootCmd.AddCommand(resetstatsCmd)
}

