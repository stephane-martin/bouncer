package cmd

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/asn1"

	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

var public_key_path string

// test-parse-backend-jwtCmd represents the test-parse-backend-jwt command
var testParseBackendJwtCmd = &cobra.Command{
	Use:   "test-parse-backend-jwt 'token'",
	Short: "Verify and parse a backend JWT token",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		if len(args) == 0 {
			fmt.Println("Specify a token to check")
			os.Exit(-1)
		}
		arg := strings.TrimSpace(args[0])
		if arg == "-" {
			reader := bufio.NewReader(os.Stdin)
			arg, err = reader.ReadString('\n')
			if err != nil && err != io.EOF {
				fmt.Printf("Error while reading stdin: %s\n", err)
				os.Exit(-1)
			}
			arg = strings.Trim(arg, "\n\r\t ")
		}
		token, err := TestParseJwt(arg, FindPublicKey())
		if err != nil {
			fmt.Printf("Failed to verify the token: %s\n", err)
			os.Exit(-1)
		}
		if !token.Valid {
			fmt.Println("Token is not valid")
			os.Exit(-1)
		}
		fmt.Println("Token is valid")
		if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
			fmt.Printf("Subject: %s\n", claims.Subject)
			fmt.Printf("Issued at: %s\n", time.Unix(claims.IssuedAt, 0).Format(time.RFC3339))
			fmt.Printf("Not before: %s\n", time.Unix(claims.NotBefore, 0).Format(time.RFC3339))
			fmt.Printf("Issuer: %s\n", claims.Issuer)
			fmt.Printf("Audience: %s\n", claims.Audience)
			fmt.Printf("ID: %s\n", claims.Id)
		} else {
			fmt.Println("Can't find the claims")
			os.Exit(-1)
		}
	},
}

func FindPublicKey() *rsa.PublicKey {
	public_key_path = strings.TrimSpace(public_key_path)
	if len(public_key_path) > 0 {
		var err error
		var err2 error
		var err3 error
		var rsakey *rsa.PublicKey
		var key interface{}
		var ok bool
		var key_b []byte
		var cert *x509.Certificate
		
		key_b, err = ioutil.ReadFile(public_key_path)	
		if err != nil {
			fmt.Printf("Error reading the public key file: %s\n", err)
			os.Exit(-1)
		}
		key_p, _ := pem.Decode(key_b)
		if key_p == nil {
			fmt.Println("Failed to PEM-parse the public key")
			os.Exit(-1)
		}

		key, err = x509.ParsePKIXPublicKey(key_p.Bytes)
		if err != nil {
			cert, err2 = x509.ParseCertificate(key_p.Bytes)
			if err2 != nil {
				var k rsa.PublicKey
				_, err3 = asn1.Unmarshal(key_p.Bytes, &k)
				if err3 != nil {
					fmt.Println("Failed to parse the public key")
					fmt.Println(err)
					fmt.Println(err2)
					fmt.Println(err3)
					os.Exit(-1)
				} else {
					key = &k 
				}
			} else {
				key = cert.PublicKey
			}
		}
		rsakey, ok = key.(*rsa.PublicKey)
		if !ok {
			fmt.Println("The public key is no a RSA key")
			os.Exit(-1)
		}

		return rsakey		
	}

	c, _, err := conf.Load(ConfigDir, ConsulAddr, ConsulPrefix, ConsulToken, ConsulDatacenter, nil)
	if err != nil {
		log.Log.WithError(err).Error("Error loading configuration")
		os.Exit(-1)
	}

	if c.Signature.PublicKey == nil {
		fmt.Sprintf("No public key was provided to verify the token signature")
		os.Exit(-1)
	}
	return c.Signature.PublicKey
}

func TestParseJwt(token_s string, key *rsa.PublicKey) (*jwt.Token, error) {


	get_public_key := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		if key == nil {
			return nil, fmt.Errorf("No key has been configured")
		}
		return key, nil
	}

	token, err := jwt.ParseWithClaims(token_s, &jwt.StandardClaims{}, get_public_key)
	if err != nil {
		return nil, err
	}
	return token, nil

}

func init() {
	RootCmd.AddCommand(testParseBackendJwtCmd)
	testParseBackendJwtCmd.Flags().StringVar(&public_key_path, "key-path", "", "Path to the RSA public key file to verify the token")
}

