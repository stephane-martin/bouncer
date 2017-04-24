package auth

import (
	"crypto/tls"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	mytls "github.com/stephane-martin/nginx-auth-ldap/tls"
	ldap "gopkg.in/ldap.v2"
)

type LdapOpError struct {
	Err error
}

func (e *LdapOpError) WrappedErrors() []error {
	return []error{e.Err}
}

func (e *LdapOpError) Error() string {
	return e.Err.Error()
}

type LdapAuthError struct {
	Err error
}

func (e *LdapAuthError) WrappedErrors() []error {
	return []error{e.Err}
}

func (e *LdapAuthError) Error() string {
	return e.Err.Error()
}

func Authenticate(username string, password string, config *conf.GlobalConfig) error {
	if config.Ldap.AuthType == "directbind" {
		return DirectBind(username, password, config)
	} else if config.Ldap.AuthType == "search" {
		return Search(username, password, config)
	} else {
		return fmt.Errorf("Unknown LDAP authentication type")
	}
}

func GetLdapClient(c *conf.GlobalConfig) (conn *ldap.Conn, err error) {
	var tls_config *tls.Config

	if c.Ldap.TlsType == "starttls" || c.Ldap.TlsType == "tls" {
		tls_config, err = mytls.GetTLSConfig(c.Ldap.Cert, c.Ldap.Key, c.Ldap.CA, c.Ldap.Insecure)
		if err != nil {
			return nil, errwrap.Wrapf("Error building the LDAP TLS configuration: {{err}}", &LdapOpError{err})
		}
	}

	addr := fmt.Sprintf("%s:%d", c.Ldap.Host, c.Ldap.Port)

	if c.Ldap.TlsType == "tls" {
		conn, err = ldap.DialTLS("tcp", addr, tls_config)
	} else {
		conn, err = ldap.Dial("tcp", addr)
	}
	if err != nil {
		return nil, errwrap.Wrapf("Error connecting to the LDAP server: {{err}}", &LdapOpError{err})
	}

	if c.Ldap.TlsType == "starttls" {
		err = conn.StartTLS(tls_config)
		if err != nil {
			return nil, errwrap.Wrapf("Error performing StartTLS: {{err}}", &LdapOpError{err})
		}
	}
	return conn, nil
}

func CheckLdapConn(c *conf.GlobalConfig) error {
	conn, err := GetLdapClient(c)
	if err != nil {
		return errwrap.Wrapf("Error connecting to LDAP: {{err}}", err)
	}
	defer conn.Close()
	if c.Ldap.AuthType == "search" {
		err = conn.Bind(c.Ldap.BindDn, c.Ldap.BindPassword)
		if err != nil {
			return errwrap.Wrapf("LDAP Bind failed. Incorrect Bind DN or Bind password? : {{err}}", &LdapOpError{err})
		}
	}
	return nil
}
