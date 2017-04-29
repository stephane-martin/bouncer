package auth

import (
	"fmt"

	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/hashicorp/errwrap"
)

func DirectBind(username string, password string, l *conf.LdapConfig) error {
	conn, err := GetLdapClient(l)
	if err != nil {
		return errwrap.Wrapf("Error getting LDAP client: {{err}}", &LdapOpError{err})	
	}
	defer conn.Close()
	user_dn := fmt.Sprintf(l.UserDnTemplate, username)

	err = conn.Bind(user_dn, password)
	if err != nil {
		return errwrap.Wrapf("LDAP Direct Bind failed. Non-existent user or incorrect password?", &LdapAuthError{err})
	}
	return nil
}
