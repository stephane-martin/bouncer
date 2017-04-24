package auth

import (
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	ldap "gopkg.in/ldap.v2"
)

func Search(username string, password string, config *conf.GlobalConfig) error {

	conn, err := GetLdapClient(config)
	if err != nil {
		return errwrap.Wrapf("Error getting LDAP client: {{err}}", &LdapOpError{err})		
	}
	defer conn.Close()

	err = conn.Bind(config.Ldap.BindDn, config.Ldap.BindPassword)
	if err != nil {
		return errwrap.Wrapf("LDAP Bind failed. Incorrect Bind DN or Bind password? : {{err}}", &LdapOpError{err})
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
		return errwrap.Wrapf("LDAP Search failed: {{err}}", &LdapOpError{err})
	}

	if len(result.Entries) != 1 {
		return errwrap.Wrapf("User does not exist in LDAP (or too many entries returned)", &LdapAuthError{err})
	}

	userdn := result.Entries[0].DN

	// Bind as the user to verify their password
	err = conn.Bind(userdn, password)
	if err != nil {
		return errwrap.Wrapf("Second LDAP bind failed. Incorrect password?", &LdapAuthError{err})
	}

	return nil
}
