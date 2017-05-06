package auth

import (
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	ldap "gopkg.in/ldap.v2"
)

func DirectBind(username string, password string, l *conf.LdapConfig) (string, string, error) {
	conn, err := GetLdapClient(l)
	if err != nil {
		return "", "", errwrap.Wrapf("Error getting LDAP client: {{err}}", &LdapOpError{err})
	}
	defer conn.Close()
	user_dn := fmt.Sprintf(l.UserDnTemplate, username)
	log.Log.WithField("DN", user_dn).Debug("Binding")
	err = conn.Bind(user_dn, password)
	if err != nil {
		return "", "", errwrap.Wrapf("LDAP Direct Bind failed. Non-existent user or incorrect password?", &LdapAuthError{err})
	}

	attributes := []string{"dn", l.UsernameAttribute}
	if l.ReturnMail {
		attributes = append(attributes, l.MailAttribute)
	}
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		user_dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		log.Log.WithError(err).Warn("LDAP Direct Bind: failed to search the user")
		return "", "", nil
	}

	if len(result.Entries) != 1 {
		log.Log.WithError(err).WithField("nb_answer", len(result.Entries)).Warn("Searching the current user does not give a unique answer")
		return "", "", nil
	}

	username = result.Entries[0].GetAttributeValue(l.UsernameAttribute)
	email := ""
	if l.ReturnMail {
		email = result.Entries[0].GetAttributeValue(l.MailAttribute)
	}

	return username, email, nil
}
