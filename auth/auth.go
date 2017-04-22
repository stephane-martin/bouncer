package auth

import (
	"fmt"

	"github.com/stephane-martin/nginx-auth-ldap/conf"
)

func Authenticate(username string, password string, config *conf.GlobalConfig) error {
	if config.Ldap.AuthType == "directbind" {
		return DirectBind(username, password, config)
	} else if config.Ldap.AuthType == "search" {
		return Search(username, password, config)
	} else {
		return fmt.Errorf("Unknown LDAP authentication type")
	}
}
