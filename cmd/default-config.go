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
)

// default-configCmd represents the default-config command
var defaultconfigCmd = &cobra.Command{
	Use:   "default-config",
	Short: "Prints the default configuration",
	Long:  "Prints the default configuration",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := conf.Load("/nonexistent")
		if err != nil {
			log.Log.WithError(err).Error("Error loading configuration")
			os.Exit(-1)
		}
		fmt.Println(config.Export())
	},
}

func init() {
	RootCmd.AddCommand(defaultconfigCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// default-configCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// default-configCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
