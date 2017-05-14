package auth

import (
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/bouncer/log"
	"github.com/stephane-martin/bouncer/conf"
	ldap "gopkg.in/ldap.v2"
)

func Search(username string, password string, l *conf.LdapConfig) (string, string, error) {

	conn, err := GetLdapClient(l)
	if err != nil {
		return "", "", errwrap.Wrapf("Error getting LDAP client: {{err}}", &LdapOpError{err})		
	}
	defer conn.Close()

	err = conn.Bind(l.BindDn, l.BindPassword)
	if err != nil {
		return "", "", errwrap.Wrapf("LDAP Bind failed. Incorrect Bind DN or Bind password? : {{err}}", &LdapOpError{err})
	}

	filter := fmt.Sprintf(l.UserSearchFilter, username)
	log.Log.WithField("filter", filter).Debug("Searching this user")

	attributes := []string{"dn", l.UsernameAttribute}
	if l.ReturnMail {
		attributes = append(attributes, l.MailAttribute)
	}
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		l.UserSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", "", errwrap.Wrapf("LDAP Search failed: {{err}}", &LdapOpError{err})
	}

	if len(result.Entries) != 1 {
		return "", "", &LdapAuthError{fmt.Errorf("User does not exist in LDAP (or too many entries returned")}
	}

	userdn := result.Entries[0].DN
	username = result.Entries[0].GetAttributeValue(l.UsernameAttribute)
	email := ""
	if l.ReturnMail {
		email = result.Entries[0].GetAttributeValue(l.MailAttribute)
	}

	// Bind as the user to verify their password
	err = conn.Bind(userdn, password)
	if err != nil {
		return "", "", errwrap.Wrapf("Second LDAP bind failed. Incorrect password?", &LdapAuthError{err})
	}

	return username, email, nil
}
