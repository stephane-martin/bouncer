package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

var disco bool

var printconfigCmd = &cobra.Command{
	Use:   "print-config",
	Short: "Print the current configuration as TOML",
	Long: `You can use print-config to check what is the real configuration
that nginx-auth-ldap will use, merging your configuration and the defaults.`,
	Run: func(cmd *cobra.Command, args []string) {

		config, _, err := conf.Load(ConfigDir, ConsulAddr, ConsulPrefix, ConsulToken, ConsulDatacenter, nil)
		if err != nil {
			log.Log.WithError(err).Error("Error loading configuration")
			os.Exit(-1)
		}


		var discovery *conf.DiscoveryLdap

	
		fmt.Println(config.Export())

		if disco && len(ConsulAddr) > 0 && len(ConsulLdapServiceName) > 0 {
			// discover LDAP servers through Consul health checks
			discovery, err = conf.NewDiscoveryLdap(config, ConsulAddr, ConsulToken, ConsulLdapDatacenter, ConsulLdapTag, ConsulLdapServiceName)
			if err != nil {
				log.Log.WithError(err).Error("Error initializing LDAP discovery. Discovery is disabled.")
			} else {
				discovery.Watch()
				defer discovery.StopWatch()

				fmt.Println("\nDiscovered LDAP\n===============")
				servers := discovery.Get()
				for _, server := range servers {
					fmt.Println(server)
				}
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(printconfigCmd)
	printconfigCmd.Flags().BoolVar(&disco, "discover", false, "Also prints discovered LDAP servers")
}
