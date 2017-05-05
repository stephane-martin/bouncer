package cmd

import (
	"fmt"
	"os"
	"strconv"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/asn1"

	"github.com/spf13/cobra"
)

// generate-rsa-keysCmd represents the generate-rsa-keys command
var generateRsaKeysCmd = &cobra.Command{
	Use:   "generate-rsa-keys 'keysize'",
	Short: "Generate private and public RSA keys",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Specify key zize in bits")
			os.Exit(-1)
		}
		b, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			fmt.Println("The argument is not an integer")
			os.Exit(-1)
		}
		bits := int(b)

		private_key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			fmt.Printf("Error generating the private key: %s\n", err)
		}
		private_key_pem := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(private_key),
		}
		private_key_serialized := pem.EncodeToMemory(private_key_pem)
		fmt.Println()
		fmt.Println(string(private_key_serialized))
		fmt.Println()

		asn_b, _ := asn1.Marshal(private_key.PublicKey)
		public_key_pem := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn_b,
		}
		public_key_serialized := pem.EncodeToMemory(public_key_pem)
		fmt.Println(string(public_key_serialized))
		fmt.Println()

	},
}

func init() {
	RootCmd.AddCommand(generateRsaKeysCmd)
}
