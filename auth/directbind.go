package auth

import (
	"crypto/tls"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	mytls "github.com/stephane-martin/nginx-auth-ldap/tls"
	ldap "gopkg.in/ldap.v2"
)

func DirectBind(username string, password string, config *conf.GlobalConfig) error {
	var err error
	var tls_config *tls.Config
	var conn *ldap.Conn

	if config.Ldap.TlsType == "starttls" || config.Ldap.TlsType == "tls" {
		tls_config, err = mytls.GetTLSConfig(config.Ldap.Cert, config.Ldap.Key, config.Ldap.CA, config.Ldap.Insecure)
		if err != nil {
			return errwrap.Wrapf("Error building the LDAP TLS configuration", err)
		}
	}

	addr := fmt.Sprintf("%s:%d", config.Ldap.Host, config.Ldap.Port)

	if config.Ldap.TlsType == "tls" {
		conn, err = ldap.DialTLS("tcp", addr, tls_config)
	} else {
		conn, err = ldap.Dial("tcp", addr)
	}
	if err != nil {
		return errwrap.Wrapf("Error connecting to the LDAP directory", err)
	}
	defer conn.Close()

	if config.Ldap.TlsType == "starttls" {
		err = conn.StartTLS(tls_config)
		if err != nil {
			return errwrap.Wrapf("Error performing StartTLS", err)
		}
	}

	user_dn := fmt.Sprintf(config.Ldap.UserDnTemplate, username)

	err = conn.Bind(user_dn, password)
	if err != nil {
		return errwrap.Wrapf("Direct bind failed. Incorrect user password?", err)
	}
	return nil
}
