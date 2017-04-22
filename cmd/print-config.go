package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

// print-configCmd represents the print-config command
var printconfigCmd = &cobra.Command{
	Use:   "print-config",
	Short: "Print the current configuration as TOML",
	Long: `You can use print-config to check what is the real configuration
that nginx-auth-ldap will use, merging your configuration and the defaults.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := conf.Load(ConfigDir)
		if err != nil {
			log.Log.WithError(err).Error("Error loading configuration")
			os.Exit(-1)
		}
		fmt.Println(config.Export())
	},
}

func init() {
	RootCmd.AddCommand(printconfigCmd)
}
