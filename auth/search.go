package auth

import (
	"crypto/tls"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	mytls "github.com/stephane-martin/nginx-auth-ldap/tls"
	ldap "gopkg.in/ldap.v2"
)

func Search(username string, password string, config *conf.GlobalConfig) error {
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

	err = conn.Bind(config.Ldap.BindDn, config.Ldap.BindPassword)
	if err != nil {
		return errwrap.Wrapf("Bind failed. Incorrect bind DN or password?", err)
	}

	filter := fmt.Sprintf(config.Ldap.UserSearchFilter, username)
	log.Log.WithField("filter", filter).Debug("Searching this user")

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		config.Ldap.UserSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return errwrap.Wrapf("LDAP Search failed", err)
	}

	if len(result.Entries) != 1 {
		return fmt.Errorf("User does not exist (or too many entries returned)")
	}

	userdn := result.Entries[0].DN

	// Bind as the user to verify their password
	err = conn.Bind(userdn, password)
	if err != nil {
		return errwrap.Wrapf("Second bind failed. Incorrect user password?", err)
	}

	return nil
}
