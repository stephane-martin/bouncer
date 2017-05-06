package auth

import (
	"crypto/tls"
	"fmt"
	"math/rand"

	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
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

type NoLdapServer struct {}

func (e *NoLdapServer) Error() string {
	return "No LDAP server is available"
}

func Authenticate(username string, password string, c *conf.GlobalConfig, discovery *conf.DiscoveryLdap) (string, string, error) {
	var err error
	// try each LDAP configuration in a random order until we get a response
	ldap_servers := []conf.LdapConfig{}
	// statically configured LDAP servers
	for _, server := range c.Ldap {
		ldap_servers = append(ldap_servers, server)
	}
	if discovery != nil {
		// discovered LDAP servers
		for _, server := range discovery.Get() {
			ldap_servers = append(ldap_servers, server)
		}
	}
	if len(ldap_servers) == 0 {
		return "", "", &NoLdapServer{}	
	}
	username_out := ""
	email := ""
	for _, i := range rand.Perm(len(ldap_servers)) {
		l := ldap_servers[i]

		log.Log.WithField("host", l.Host).WithField("port", l.Port).Debug("Trying LDAP server")
		if l.AuthType == "directbind" {
			username_out, email, err = DirectBind(username, password, &l)
		} else if l.AuthType == "search" {
			username_out, email, err = Search(username, password, &l)
		} else {
			return "", "", fmt.Errorf("Unknown LDAP authentication type")
		}
		if err == nil {
			return username_out, email, nil
		}
		if errwrap.ContainsType(err, new(LdapOpError)) {
			// Operational Error => try next LDAP server...
			log.Log.WithError(err).Warn("LDAP operational error")
			continue
		}
		// authentication fails, return the failure
		return "", "", err
	}
	// return the last (operational) error
	return "", "", err
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

func CheckLdapConn(c *conf.GlobalConfig, discovery *conf.DiscoveryLdap) error {
	// check that we can connect to at least one LDAP server
	var err error
	ldap_servers := []conf.LdapConfig{}
	for _, server := range c.Ldap {
		ldap_servers = append(ldap_servers, server)
	}
	if discovery != nil {
		// discovered LDAP servers
		for _, server := range discovery.Get() {
			ldap_servers = append(ldap_servers, server)
		}
	}
	if len(ldap_servers) == 0 {
		return &NoLdapServer{}	
	}
	
	for _, l := range ldap_servers {
		err = CheckOneLdapConn(&l)
		if err == nil {
			log.Log.WithField("host", l.Host).WithField("port", l.Port).Debug("CheckLdapConn success")
			return nil
		} else {
			log.Log.WithError(err).WithField("host", l.Host).WithField("port", l.Port).Warn("CheckLdapConn failed")
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
