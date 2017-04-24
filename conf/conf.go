package conf

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis"
	"github.com/hashicorp/errwrap"
	"github.com/spf13/viper"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

type GlobalConfig struct {
	Ldap  LdapConfig  `mapstructure:"ldap" toml:"ldap"`
	Http  HttpConfig  `mapstructure:"http" toml:"http"`
	Cache CacheConfig `mapstructure:"cache" toml:"cache"`
	Redis RedisConfig `mapstructure:"redis" toml:"redis"`
}

type LdapConfig struct {
	Host             string `mapstructure:"host" toml:"host"`
	Port             uint32 `mapstructure:"port" toml:"port"`
	AuthType         string `mapstructure:"auth_type" toml:"auth_type"`
	BindDn           string `mapstructure:"bind_dn" toml:"bind_dn"`
	BindPassword     string `mapstructure:"bind_password" toml:"bind_password"`
	UserSearchFilter string `mapstructure:"user_search_filter" toml:"user_search_filter"`
	UserSearchBase   string `mapstructure:"user_search_base" toml:"user_search_base"`
	UserDnTemplate   string `mapstructure:"user_dn_template" toml:"user_dn_template"`
	TlsType          string `mapstructure:"tls_type" toml:"tls_type"`
	CA               string `mapstructure:"certificate_authority" toml:"certificate_authority"`
	Cert             string `mapstructure:"certificate" toml:"certificate"`
	Key              string `mapstructure:"key" toml:"key"`
	Insecure         bool   `mapstructure:"insecure" toml:"insecure"`
}

type HttpConfig struct {
	BindAddr            string `mapstructure:"bind_addr" toml:"bind_addr"`
	Port                uint32 `mapstructure:"port" toml:"port"`
	Realm               string `mapstructure:"realm" toml:"realm"`
	AuthorizationHeader string `mapstructure:"authorization_header" toml:"authorization_header"`
	AuthenticateHeader  string `mapstructure:"authenticate_header" toml:"authenticate_header"`
	OriginalUriHeader   string `mapstructure:"original_uri_header" toml:"original_uri_header"`
	OriginalHostHeader  string `mapstructure:"original_host_header" toml:"original_host_header"`
	OriginalPortHeader  string `mapstructure:"original_port_header" toml:"original_port_header"`
	OriginalProtoHeader string `mapstructure:"original_proto_header" toml:"original_proto_header"`
	FailedAuthDelay     uint32 `mapstructure:"failed_auth_delay_seconds" toml:"failed_auth_delay_seconds"`
	ShutdownTimeout     uint32 `mapstructure:"shutdown_timeout_seconds" toml:"shutdown_timeout_seconds"`
	Https               bool   `mapstructure:"https" toml:"https"`
	Certificate         string `mapstructure:"certificate" toml:"certificate"`
	Key                 string `mapstructure:"key" toml:"key"`
}

type CacheConfig struct {
	Expires int32  `mapstructure:"expires_seconds" toml:"expires_seconds"`
	Secret  string `mapstructure:"secret" toml:"secret"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host" toml:"host"`
	Port     uint32 `mapstructure:"port" toml:"port"`
	Database uint8  `mapstructure:"database" toml:"database"`
	Password string `mapstructure:"password" toml:"password"`
	Poolsize uint32 `mapstructure:"poolsize" toml:"poolsize"`
	Enabled  bool   `mapstructure:"enabled" toml:"enabled"`
	Expires  int64  `mapstructure:"expires_seconds" toml:"expires_seconds"`
}

func New() *GlobalConfig {
	return &GlobalConfig{
		Ldap:  LdapConfig{},
		Http:  HttpConfig{},
		Cache: CacheConfig{},
	}
}

func (c *GlobalConfig) Export() string {
	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	encoder.Encode(*c)
	return buf.String()
}

func (c *GlobalConfig) CheckRedisConn() error {
	conn := c.GetRedisClient()
	defer conn.Close()
	return conn.Ping().Err()
}

func (c *GlobalConfig) GetRedisOptions() (opts *redis.Options) {
	opts = &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port),
		Network:  "tcp",
		DB:       int(c.Redis.Database),
		PoolSize: int(c.Redis.Poolsize),
	}
	if len(c.Redis.Password) > 0 {
		opts.Password = c.Redis.Password
	}
	return opts
}

func (c *GlobalConfig) GetRedisClient() *redis.Client {
	return redis.NewClient(c.GetRedisOptions())
}

func (c *GlobalConfig) GenerateSecret() (secret []byte, err error) {
	if len(c.Cache.Secret) == 0 {
		secret = make([]byte, 32)
		_, err = rand.Read(secret)
		if err != nil {
			return nil, err
		}
	} else {
		secret = []byte(c.Cache.Secret)
	}
	return secret, nil
}

func (c *GlobalConfig) Check() error {
	if c.Ldap.Port == 0 {
		return fmt.Errorf("LDAP port can't be 0")
	}

	switch c.Ldap.AuthType {
	case "directbind":
	case "search":
	default:
		return fmt.Errorf("LDAP auth_type must be 'search' or 'directbind'")
	}

	if c.Ldap.AuthType == "search" && (len(c.Ldap.BindDn) == 0 || len(c.Ldap.BindPassword) == 0) {
		return fmt.Errorf("LDAP auth_type is 'search': specify 'bind_dn' and 'bind_password'")
	}

	if c.Ldap.AuthType == "search" && len(c.Ldap.UserSearchBase) == 0 {
		return fmt.Errorf("LDAP auth_type is 'search': specify 'user_search_base'")
	}

	if c.Ldap.AuthType == "directbind" && len(c.Ldap.UserDnTemplate) == 0 {
		return fmt.Errorf("LDAP auth_type is 'directbind': specify 'user_dn_template'")
	}

	switch c.Ldap.TlsType {
	case "none":
	case "starttls":
	case "tls":
	default:
		return fmt.Errorf("LDAP tls_type must be 'none', 'starttls' or 'tls'")
	}

	if c.Ldap.TlsType == "tls" || c.Ldap.TlsType == "starttls" {
		if !c.Ldap.Insecure && len(c.Ldap.CA) == 0 {
			return fmt.Errorf("Specify the certificate authority 'ldap.certificate_authority' that is used to verify the LDAP server certificate")
		}
	}

	if c.Http.Port == 0 {
		return fmt.Errorf("HTTP port can't be 0")
	}

	if c.Http.Https && (len(c.Http.Certificate) == 0 || len(c.Http.Key) == 0) {
		return fmt.Errorf("HTTPS is active: specify the HTTPS certificate and the HTTPS private key")
	}

	if c.Redis.Port == 0 {
		return fmt.Errorf("Redis port can't be 0")
	}

	if c.Redis.Poolsize == 0 {
		return fmt.Errorf("Redis pool size can't be 0")
	}

	return nil
}

func Load(dirname string) (*GlobalConfig, error) {
	v := viper.New()

	v.SetDefault("ldap.host", "127.0.0.1")
	v.SetDefault("ldap.port", 389)
	v.SetDefault("ldap.auth_type", "directbind")
	v.SetDefault("ldap.bind_dn", "")
	v.SetDefault("ldap.bind_password", "")
	v.SetDefault("ldap.user_search_filter", "(uid=%s)")
	v.SetDefault("ldap.user_search_base", "ou=users,dc=example,dc=org")
	v.SetDefault("ldap.user_dn_template", "uid=%s,ou=users,dc=example,dc=org")
	v.SetDefault("ldap.tls_type", "none")
	v.SetDefault("ldap.certificate_authority", "")
	v.SetDefault("ldap.certificate", "")
	v.SetDefault("ldap.key", "")
	v.SetDefault("ldap.insecure", false)

	v.SetDefault("http.bind_addr", "0.0.0.0")
	v.SetDefault("http.port", 8080)
	v.SetDefault("http.realm", "Example Realm")
	v.SetDefault("http.authorization_header", "Authorization")
	v.SetDefault("http.authenticate_header", "WWW-Authenticate")
	v.SetDefault("http.original_uri_header", "X-Original-Uri")
	v.SetDefault("http.original_host_header", "X-Forwarded-Host")
	v.SetDefault("http.original_port_header", "X-Forwarded-Port")
	v.SetDefault("http.original_proto_header", "X-Forwarded-Proto")
	v.SetDefault("http.failed_auth_delay_seconds", 2)
	v.SetDefault("http.shutdown_timeout_seconds", 2)
	v.SetDefault("http.https", false)
	v.SetDefault("http.certificate", "")
	v.SetDefault("http.key", "")

	v.SetDefault("cache.expires_seconds", 300)
	v.SetDefault("cache.secret", "")

	v.SetDefault("redis.host", "127.0.0.1")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.database", 0)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.poolsize", 10)
	v.SetDefault("redis.enabled", false)
	v.SetDefault("redis.expires_seconds", 86400)

	v.BindEnv("ldap.host", "NAL_LDAP_HOST")
	v.BindEnv("ldap.port", "NAL_LDAP_PORT")
	v.BindEnv("ldap.auth_type", "NAL_AUTH_TYPE")
	v.BindEnv("ldap.bind_dn", "NAL_BIND_DN")
	v.BindEnv("ldap.bind_password", "NAL_BIND_PASSWORD")
	v.BindEnv("ldap.user_search_filter", "NAL_SEARCH_FILTER")
	v.BindEnv("ldap.user_search_base", "NAL_SEARCH_BASE")
	v.BindEnv("ldap.user_dn_template", "NAL_USER_TEMPLATE")
	v.BindEnv("ldap.tls_type", "NAL_LDAP_TLS")
	v.BindEnv("ldap.certificate_authority", "NAL_LDAP_CA")
	v.BindEnv("ldap.certificate", "NAL_LDAP_CERT")
	v.BindEnv("ldap.key", "NAL_LDAP_KEY")
	v.BindEnv("ldap.insecure", "NAL_LDAP_INSECURE")

	v.BindEnv("http.bind_addr", "NAL_HTTP_ADDR")
	v.BindEnv("http.port", "NAL_HTTP_PORT")
	v.BindEnv("http.realm", "NAL_REALM")
	v.BindEnv("http.authorization_header", "NAL_AUTHORIZATION")
	v.BindEnv("http.authenticate_header", "NAL_AUTHENTICATE")
	v.BindEnv("http.original_uri_header", "NAL_ORIGINAL_URI")
	v.BindEnv("http.original_host_header", "NAL_ORIGINAL_HOST")
	v.BindEnv("http.original_proto_header", "NAL_ORIGINAL_PROTO")
	v.BindEnv("http.original_port_header", "NAL_ORIGINAL_PORT")
	v.BindEnv("http.failed_auth_delay_seconds", "NAL_FAILED_DELAY")
	v.BindEnv("http.shutdown_timeout_seconds", "NAL_SHUTDOWN_TIMEOUT")
	v.BindEnv("http.https", "NAL_HTTPS")
	v.BindEnv("http.certificate", "NAL_HTTPS_CERTIFICATE")
	v.BindEnv("http.key", "NAL_HTTPS_KEY")

	v.BindEnv("cache.expires_seconds", "NAL_CACHE_EXPIRES")
	v.BindEnv("cache.secret", "NAL_CACHE_SECRET")

	v.BindEnv("redis.host", "NAL_REDIS_HOST")
	v.BindEnv("redis.port", "NAL_REDIS_PORT")
	v.BindEnv("redis.database", "NAL_REDIS_DATABASE")
	v.BindEnv("redis.password", "NAL_REDIS_PASSWORD")
	v.BindEnv("redis.poolsize", "NAL_REDIS_POOLSIZE")
	v.BindEnv("redis.enabled", "NAL_REDIS_ENABLED")
	v.BindEnv("redis.expires_seconds", "NAL_REDIS_EXPIRES")

	v.SetConfigName("nginx-auth-ldap")

	dirname = strings.TrimSpace(dirname)
	if len(dirname) > 0 {
		v.AddConfigPath(dirname)
	}
	if dirname != "/nonexistent" {
		v.AddConfigPath("/etc")
	}

	err := v.ReadInConfig()
	if err == nil {
		log.Log.WithField("file", v.ConfigFileUsed()).Debug("Found configuration file")
	} else {
		switch err := err.(type) {
		default:
			return nil, errwrap.Wrapf("Error reading the configuration file", err)
		case viper.ConfigFileNotFoundError:
			log.Log.WithError(err).Info("No configuration file was found")
		}
	}

	conf := New()
	err = v.Unmarshal(conf)
	if err != nil {
		return nil, errwrap.Wrapf("Error parsing configuration", err)
	}

	err = conf.Check()
	if err != nil {
		return nil, err
	}

	return conf, nil

}
