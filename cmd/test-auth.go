package cmd

import (
	"os"

	"github.com/segmentio/go-prompt"
	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/auth"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

var username string
var password string

// test-authCmd represents the test-auth command
var testauthCmd = &cobra.Command{
	Use:   "test-auth",
	Short: "Check that authentication is working correctly",
	Long: `With the test-auth command you can check that LDAP authentication
works for a single username and password.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(username) == 0 {
			username = prompt.StringRequired("Username")
		}
		if len(password) == 0 {
			password = prompt.PasswordMasked("Password")
		}
		if len(password) == 0 {
			log.Log.Error("Empty password")
			os.Exit(-1)
		}

		config, err := conf.Load(ConfigDir)
		if err != nil {
			log.Log.WithError(err).Error("Error loading configuration")
			os.Exit(-1)
		}

		err = auth.Authenticate(username, password, config)
		if err != nil {
			log.Log.WithError(err).Error("Authentication failed")
			os.Exit(-1)
		} else {
			log.Log.Info("Authentication is successful")
		}
	},
}

func init() {
	RootCmd.AddCommand(testauthCmd)
	testauthCmd.Flags().StringVar(&username, "username", "", "Username")
	testauthCmd.Flags().StringVar(&password, "password", "", "Password")
}
