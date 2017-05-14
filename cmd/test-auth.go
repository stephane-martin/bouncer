package cmd

import (
	"os"

	"github.com/segmentio/go-prompt"
	"github.com/spf13/cobra"
	"github.com/stephane-martin/bouncer/auth"
	"github.com/stephane-martin/bouncer/conf"
	"github.com/stephane-martin/bouncer/log"
)

var username string
var password string
var uri string

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

		config, _, err := conf.Load(ConfigDir, ConsulAddr, ConsulPrefix, ConsulToken, ConsulDatacenter, nil)
		if err != nil {
			log.Log.WithError(err).Error("Error loading configuration")
			os.Exit(-1)
		}

		var discovery *conf.DiscoveryLdap
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

		username_out, email, err := auth.Authenticate(username, password, config, discovery)
		if err != nil {
			log.Log.WithError(err).Error("Authentication failed")
			os.Exit(-1)
		} else {
			log.Log.WithField("username_in", username).WithField("username_out", username_out).WithField("email", email).
				Info("Authentication is successful")
		}
	},
}

func init() {
	RootCmd.AddCommand(testauthCmd)
	testauthCmd.Flags().StringVar(&username, "username", "", "Username")
	testauthCmd.Flags().StringVar(&password, "password", "", "Password")
	testauthCmd.Flags().StringVar(&uri, "uri", "", "Requested URI")
}
