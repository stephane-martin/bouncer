package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/stephane-martin/bouncer/conf"
	"github.com/stephane-martin/bouncer/log"
)

var discoveredCmd = &cobra.Command{
	Use:   "discovered",
	Short: "Print the LDAP servers that can be discovered through Consul",
	Long: `To check that your LDAP services are correctly defined in Consul,
you can use the discovered command. It prints the actual LDAP servers that are
currently visible.`,
	Run: func(cmd *cobra.Command, args []string) {
		discovered()
	},
}

func init() {
	RootCmd.AddCommand(discoveredCmd)
}

func discovered() {
	if len(ConsulAddr) == 0 {
		log.Log.Error("Provide Consul host")
		os.Exit(-1)
	}
	if len(ConsulLdapServiceName) == 0 {
		log.Log.Error("Provide Consul LDAP service name")
		os.Exit(-1)
	}
	config, _, err := conf.Load(ConfigDir, ConsulAddr, ConsulPrefix, ConsulToken, ConsulDatacenter, nil)
	if err != nil {
		log.Log.WithError(err).Error("Error loading configuration")
		os.Exit(-1)
	}

	var discovery *conf.DiscoveryLdap
	discovery, err = conf.NewDiscoveryLdap(config, ConsulAddr, ConsulToken, ConsulLdapDatacenter, ConsulLdapTag, ConsulLdapServiceName)
	if err != nil {
		log.Log.WithError(err).Error("Error initializing LDAP discovery.")
		os.Exit(-1)
	}
	discovery.Watch()
	defer discovery.StopWatch()
	for _, server := range discovery.Get() {
		log.Log.WithField("host", server.Host).WithField("port", server.Port).Info("Discovered LDAP server")
	}
}
