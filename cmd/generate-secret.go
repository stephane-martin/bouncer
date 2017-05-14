package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephane-martin/bouncer/log"
)

// generate-secretCmd represents the generate-secret command
var generatesecretCmd = &cobra.Command{
	Use:   "generate-secret",
	Short: "Generate a secret that can be used for parameter 'cache.secret'",
	Run: func(cmd *cobra.Command, args []string) {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			log.Log.WithError(err).Error("Error generating secret")
			os.Exit(-1)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(b))
	},
}

func init() {
	RootCmd.AddCommand(generatesecretCmd)
}
