package auth

import (
	"crypto/tls"
	"fmt"
	"math/rand"

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

func Authenticate(username string, password string, c *conf.GlobalConfig) error {
	var err error
	// try each LDAP configuration in a random order until we get a response
	for _, i := range rand.Perm(len(c.Ldap)) {
		l := c.Ldap[i]
		if l.AuthType == "directbind" {
			err = DirectBind(username, password, &l)
		} else if l.AuthType == "search" {
			err = Search(username, password, &l)
		} else {
			return fmt.Errorf("Unknown LDAP authentication type")
		}
		if err == nil {
			return err
		}
		if errwrap.ContainsType(err, new(LdapOpError)) {
			// Operational Error => try next LDAP server...
			continue
		}
		// authentication fails, return the failure
		return err
	}
	// return the last (operational) error
	return err
}

func GetOneLdapConfig(c *conf.GlobalConfig) *conf.LdapConfig {
	return &c.Ldap[rand.Intn(len(c.Ldap))]
}


func GetLdapClient(l *conf.LdapConfig) (conn *ldap.Conn, err error) {

	var tls_config *tls.Config

	if l.TlsType == "starttls" || l.TlsType == "tls" {
		tls_config, err = mytls.GetTLSConfig(l.Cert, l.Key, l.CA, l.Insecure)
		if err != nil {
			return nil, errwrap.Wrapf("Error building the LDAP TLS configuration: {{err}}", &LdapOpError{err})
		}
	}

	addr := fmt.Sprintf("%s:%d", l.Host, l.Port)

	if l.TlsType == "tls" {
		conn, err = ldap.DialTLS("tcp", addr, tls_config)
	} else {
		conn, err = ldap.Dial("tcp", addr)
	}
	if err != nil {
		return nil, errwrap.Wrapf("Error connecting to the LDAP server: {{err}}", &LdapOpError{err})
	}

	if l.TlsType == "starttls" {
		err = conn.StartTLS(tls_config)
		if err != nil {
			return nil, errwrap.Wrapf("Error performing StartTLS: {{err}}", &LdapOpError{err})
		}
	}
	return conn, nil
}

func CheckLdapConn(c *conf.GlobalConfig) error {
	// check that we can connect to at least one LDAP server
	var err error
	for _, l := range c.Ldap {
		err = CheckOneLdapConn(&l)
		if err == nil {
			return nil
		}
	}
	// return last error
	return err
}

func CheckOneLdapConn(l *conf.LdapConfig) error {
	conn, err := GetLdapClient(l)
	if err != nil {
		return errwrap.Wrapf("Error connecting to LDAP: {{err}}", err)
	}
	defer conn.Close()
	if l.AuthType == "search" {
		err = conn.Bind(l.BindDn, l.BindPassword)
		if err != nil {
			return errwrap.Wrapf("LDAP Bind failed. Incorrect Bind DN or Bind password? : {{err}}", &LdapOpError{err})
		}
	}
	return nil
}
