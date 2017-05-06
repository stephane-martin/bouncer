package conf

import "github.com/spf13/viper"

func SetEnvMapping(v *viper.Viper) {
	v.BindEnv("defaultldap.host", "NAL_LDAP_HOST")
	v.BindEnv("defaultldap.port", "NAL_LDAP_PORT")
	v.BindEnv("defaultldap.auth_type", "NAL_AUTH_TYPE")
	v.BindEnv("defaultldap.bind_dn", "NAL_BIND_DN")
	v.BindEnv("defaultldap.bind_password", "NAL_BIND_PASSWORD")
	v.BindEnv("defaultldap.user_search_filter", "NAL_SEARCH_FILTER")
	v.BindEnv("defaultldap.user_search_base", "NAL_SEARCH_BASE")
	v.BindEnv("defaultldap.user_dn_template", "NAL_USER_TEMPLATE")
	v.BindEnv("defaultldap.username_attribute", "NAL_USERNAME_ATTRIBUTE")
	v.BindEnv("defaultldap.mail_attribute", "NAL_MAIL_ATTRIBUTE")
	v.BindEnv("defaultldap.return_mail", "NAL_RETURN_MAIL")
	v.BindEnv("defaultldap.tls_type", "NAL_LDAP_TLS")
	v.BindEnv("defaultldap.certificate_authority", "NAL_LDAP_CA")
	v.BindEnv("defaultldap.certificate", "NAL_LDAP_CERT")
	v.BindEnv("defaultldap.key", "NAL_LDAP_KEY")
	v.BindEnv("defaultldap.insecure", "NAL_LDAP_INSECURE")

	v.BindEnv("http.bind_addr", "NAL_HTTP_ADDR")
	v.BindEnv("http.port", "NAL_HTTP_PORT")
	v.BindEnv("http.realm", "NAL_REALM")
	v.BindEnv("http.authorization_header", "NAL_AUTHORIZATION_HEADER")
	v.BindEnv("http.authenticate_header", "NAL_AUTHENTICATE_HEADER")
	v.BindEnv("http.original_uri_header", "NAL_ORIGINAL_URI_HEADER")
	v.BindEnv("http.original_host_header", "NAL_ORIGINAL_HOST_HEADER")
	v.BindEnv("http.original_proto_header", "NAL_ORIGINAL_PROTO_HEADER")
	v.BindEnv("http.original_port_header", "NAL_ORIGINAL_PORT_HEADER")
	v.BindEnv("http.real_ip_header", "NAL_REAL_IP_HEADER")
	v.BindEnv("http.nal_cookie_header", "NAL_COOKIE_HEADER")
	v.BindEnv("http.remote_user_header", "NAL_REMOTE_USER_HEADER")
	v.BindEnv("http.jwt_header", "NAL_JWT_HEADER")
	v.BindEnv("http.failed_auth_delay_seconds", "NAL_FAILED_DELAY")
	v.BindEnv("http.shutdown_timeout_seconds", "NAL_SHUTDOWN_TIMEOUT")
	v.BindEnv("http.https", "NAL_HTTPS")
	v.BindEnv("http.certificate", "NAL_HTTPS_CERTIFICATE")
	v.BindEnv("http.key", "NAL_HTTPS_KEY")
	v.BindEnv("http.nal_cookie_name", "NAL_COOKIE_NAME")
	v.BindEnv("http.mask_password", "NAL_MASK_PASSWORD")

	v.BindEnv("api.bind_addr", "NAL_API_ADDR")
	v.BindEnv("api.port", "NAL_API_PORT")

	v.BindEnv("cache.expires", "NAL_CACHE_EXPIRES")
	v.BindEnv("cache.secret", "NAL_CACHE_SECRET")

	v.BindEnv("redis.host", "NAL_REDIS_HOST")
	v.BindEnv("redis.port", "NAL_REDIS_PORT")
	v.BindEnv("redis.database", "NAL_REDIS_DATABASE")
	v.BindEnv("redis.password", "NAL_REDIS_PASSWORD")
	v.BindEnv("redis.poolsize", "NAL_REDIS_POOLSIZE")
	v.BindEnv("redis.enabled", "NAL_REDIS_ENABLED")
	v.BindEnv("redis.expires_seconds", "NAL_REDIS_EXPIRES")

	v.BindEnv("signature.private_key_path", "NAL_PRIVATE_KEY_PATH")
}
