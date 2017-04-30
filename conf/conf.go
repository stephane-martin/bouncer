package conf

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis"
	"github.com/hashicorp/errwrap"
	"github.com/spf13/viper"
	"github.com/stephane-martin/nginx-auth-ldap/consul"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

type GlobalConfig struct {
	Ldap        []LdapConfig `mapstructure:"ldap" toml:"ldap"`
	DefaultLdap LdapConfig   `mapstructure:"defaultldap" toml:"defaultldap"`
	Http        HttpConfig   `mapstructure:"http" toml:"http"`
	Api         ApiConfig    `mapstructure:"api" toml:"api"`
	Cache       CacheConfig  `mapstructure:"cache" toml:"cache"`
	Redis       RedisConfig  `mapstructure:"redis" toml:"redis"`
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

type ApiConfig struct {
	BindAddr string `mapstructure:"bind_addr" toml:"bind_addr"`
	Port     uint32 `mapstructure:"port" toml:"port"`
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
		Ldap:  []LdapConfig{},
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

	for _, l := range c.Ldap {
		if l.Port == 0 {
			return fmt.Errorf("LDAP port can't be 0")
		}
		switch l.AuthType {
		case "directbind":
		case "search":
		default:
			return fmt.Errorf("LDAP auth_type must be 'search' or 'directbind'")
		}

		if l.AuthType == "search" && (len(l.BindDn) == 0 || len(l.BindPassword) == 0) {
			return fmt.Errorf("LDAP auth_type is 'search': specify 'bind_dn' and 'bind_password'")
		}

		if l.AuthType == "search" && len(l.UserSearchBase) == 0 {
			return fmt.Errorf("LDAP auth_type is 'search': specify 'user_search_base'")
		}

		if l.AuthType == "directbind" && len(l.UserDnTemplate) == 0 {
			return fmt.Errorf("LDAP auth_type is 'directbind': specify 'user_dn_template'")
		}

		switch l.TlsType {
		case "none":
		case "starttls":
		case "tls":
		default:
			return fmt.Errorf("LDAP tls_type must be 'none', 'starttls' or 'tls'")
		}

		if l.TlsType == "tls" || l.TlsType == "starttls" {
			if !l.Insecure && len(l.CA) == 0 {
				return fmt.Errorf("Specify the certificate authority 'ldap.certificate_authority' that is used to verify the LDAP server certificate")
			}
		}
	}

	if c.Http.Port == 0 {
		return fmt.Errorf("HTTP port can't be 0")
	}

	if c.Http.Https && (len(c.Http.Certificate) == 0 || len(c.Http.Key) == 0) {
		return fmt.Errorf("HTTPS is active: specify the HTTPS certificate and the HTTPS private key")
	}

	if c.Api.Port == 0 {
		return fmt.Errorf("API HTTP port can't be 0")
	}

	if c.Redis.Port == 0 {
		return fmt.Errorf("Redis port can't be 0")
	}

	if c.Redis.Poolsize == 0 {
		return fmt.Errorf("Redis pool size can't be 0")
	}

	return nil
}

func Load(dirname, c_addr, c_prefix, c_token, c_dtctr string, consul_notify chan bool) (conf *GlobalConfig, stop_chan chan bool, err error) {
	defer func() {
		// sometimes viper panics
		if r := recover(); r != nil {
			log.Log.WithField("recover", r).Error("Recovered in conf.Load")
			// find out exactly what the error was and set err
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
			// invalidate other returns
			conf = nil
			stop_chan = nil
		}

	}()

	// we should close consul_notify in all cases
	v := viper.New()

	v.SetDefault("defaultldap.host", "127.0.0.1")
	v.SetDefault("defaultldap.port", 389)
	v.SetDefault("defaultldap.auth_type", "directbind")
	v.SetDefault("defaultldap.bind_dn", "")
	v.SetDefault("defaultldap.bind_password", "")
	v.SetDefault("defaultldap.user_search_filter", "(uid=%s)")
	v.SetDefault("defaultldap.user_search_base", "ou=users,dc=example,dc=org")
	v.SetDefault("defaultldap.user_dn_template", "uid=%s,ou=users,dc=example,dc=org")
	v.SetDefault("defaultldap.tls_type", "none")
	v.SetDefault("defaultldap.certificate_authority", "")
	v.SetDefault("defaultldap.certificate", "")
	v.SetDefault("defaultldap.key", "")
	v.SetDefault("defaultldap.insecure", false)

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

	v.SetDefault("api.bind_addr", "127.0.0.1")
	v.SetDefault("api.port", 8081)

	v.SetDefault("cache.expires_seconds", 300)
	v.SetDefault("cache.secret", "")

	v.SetDefault("redis.host", "127.0.0.1")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.database", 0)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.poolsize", 10)
	v.SetDefault("redis.enabled", false)
	v.SetDefault("redis.expires_seconds", 86400)

	v.BindEnv("defaultldap.host", "NAL_LDAP_HOST")
	v.BindEnv("defaultldap.port", "NAL_LDAP_PORT")
	v.BindEnv("defaultldap.auth_type", "NAL_AUTH_TYPE")
	v.BindEnv("defaultldap.bind_dn", "NAL_BIND_DN")
	v.BindEnv("defaultldap.bind_password", "NAL_BIND_PASSWORD")
	v.BindEnv("defaultldap.user_search_filter", "NAL_SEARCH_FILTER")
	v.BindEnv("defaultldap.user_search_base", "NAL_SEARCH_BASE")
	v.BindEnv("defaultldap.user_dn_template", "NAL_USER_TEMPLATE")
	v.BindEnv("defaultldap.tls_type", "NAL_LDAP_TLS")
	v.BindEnv("defaultldap.certificate_authority", "NAL_LDAP_CA")
	v.BindEnv("defaultldap.certificate", "NAL_LDAP_CERT")
	v.BindEnv("defaultldap.key", "NAL_LDAP_KEY")
	v.BindEnv("defaultldap.insecure", "NAL_LDAP_INSECURE")

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

	v.BindEnv("api.bind_addr", "NAL_API_ADDR")
	v.BindEnv("api.port", "NAL_API_PORT")

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

	err = v.ReadInConfig()
	if err == nil {
		log.Log.WithField("file", v.ConfigFileUsed()).Debug("Found configuration file")
	} else {
		switch err := err.(type) {
		default:
			if consul_notify != nil {
				close(consul_notify)
			}
			return nil, nil, errwrap.Wrapf("Error reading the configuration file", err)
		case viper.ConfigFileNotFoundError:
			log.Log.WithError(err).Debug("No configuration file was found")
		}
	}

	var config_in_consul map[string]string

	if len(c_addr) > 0 {
		consul_client, err := consul.NewClient(c_addr, c_token, c_dtctr)
		if err != nil {
			if consul_notify != nil {
				close(consul_notify)
			}
			return nil, nil, err
		}
		if consul_notify == nil {
			config_in_consul, _, err = consul.WatchTree(consul_client, c_prefix, nil)
		} else {
			// responsability to close consul_notify is transfered to WatchTree
			config_in_consul, stop_chan, err = consul.WatchTree(consul_client, c_prefix, consul_notify)
		}
		if err != nil {
			return nil, nil, err
		}
		ParseConfigFromConsul(v, c_prefix, config_in_consul)
	} else {
		if consul_notify != nil {
			close(consul_notify)
		}
	}

	conf = New()
	err = v.Unmarshal(conf)
	if err != nil {
		if stop_chan != nil {
			close(stop_chan)
		}
		return nil, nil, errwrap.Wrapf("Error parsing configuration", err)
	}

	if len(config_in_consul) > 0 {
		ParseLdapConfigFromConsul(conf, c_prefix, config_in_consul)
	}

	// inject defaults into LDAP configurations
	for i, _ := range conf.Ldap {
		if conf.Ldap[i].Host == "" {
			conf.Ldap[i].Host = conf.DefaultLdap.Host
		}
		if conf.Ldap[i].Port == 0 {
			conf.Ldap[i].Port = conf.DefaultLdap.Port
		}
		if conf.Ldap[i].AuthType == "" {
			conf.Ldap[i].AuthType = conf.DefaultLdap.AuthType
		}
		if conf.Ldap[i].BindDn == "" {
			conf.Ldap[i].BindDn = conf.DefaultLdap.BindDn
		}
		if conf.Ldap[i].BindPassword == "" {
			conf.Ldap[i].BindPassword = conf.DefaultLdap.BindPassword
		}
		if conf.Ldap[i].UserSearchFilter == "" {
			conf.Ldap[i].UserSearchFilter = conf.DefaultLdap.UserSearchFilter
		}
		if conf.Ldap[i].UserSearchBase == "" {
			conf.Ldap[i].UserSearchBase = conf.DefaultLdap.UserSearchBase
		}
		if conf.Ldap[i].UserDnTemplate == "" {
			conf.Ldap[i].UserDnTemplate = conf.DefaultLdap.UserDnTemplate
		}
		if conf.Ldap[i].TlsType == "" {
			conf.Ldap[i].TlsType = conf.DefaultLdap.TlsType
		}
		if conf.Ldap[i].CA == "" {
			conf.Ldap[i].CA = conf.DefaultLdap.CA
		}
		if conf.Ldap[i].Cert == "" {
			conf.Ldap[i].Cert = conf.DefaultLdap.Cert
		}
		if conf.Ldap[i].Key == "" {
			conf.Ldap[i].Key = conf.DefaultLdap.Key
		}
		if !conf.Ldap[i].Insecure {
			conf.Ldap[i].Insecure = conf.DefaultLdap.Insecure
		}
	}

	err = conf.Check()
	if err != nil {
		if stop_chan != nil {
			close(stop_chan)
		}
		return nil, nil, err
	}

	return conf, stop_chan, nil

}

func ParseConfigFromConsul(vi *viper.Viper, prefix string, c map[string]string) {
	c_prefix := prefix + "/conf"

	for k, v := range c {
		if strings.HasPrefix(k, c_prefix) {
			k = strings.Replace(strings.Trim(k[len(c_prefix):len(k)], "/"), "/", ".", -1)
			log.Log.WithField(k, v).Debug("Config from consul")
			vi.Set(k, v)
		}
	}
}

func ParseLdapConfigFromConsul(conf *GlobalConfig, prefix string, c map[string]string) {
	l_prefix := prefix + "/ldap"

	ldap_configs := map[string]map[string]string{}

	for k, v := range c {
		if strings.HasPrefix(k, l_prefix) {
			k = strings.Replace(strings.Trim(k[len(l_prefix):len(k)], "/"), "/", ".", -1)
			splits := strings.SplitN(k, ".", 2)
			bucket := splits[0]
			k = splits[1]
			if _, exists := ldap_configs[bucket]; !exists {
				ldap_configs[bucket] = map[string]string{}
			}
			ldap_configs[bucket][k] = v
		}
	}
	for bucket, m := range ldap_configs {
		ldap_config := LdapConfig{}
		for k, v := range m {
			switch k {
			case "host":
				ldap_config.Host = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "port":
				port, err := strconv.ParseInt(v, 10, 32)
				if err == nil {
					ldap_config.Port = uint32(port)
					log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
				} else {
					log.Log.WithError(err).WithField(k, v).Warn("LDAP port in consul has wrong format. Ignoring.")
				}
			case "auth_type":
				ldap_config.AuthType = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "bind_dn":
				ldap_config.BindDn = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "bind_password":
				ldap_config.BindPassword = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "user_search_filter":
				ldap_config.UserSearchFilter = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "user_search_base":
				ldap_config.UserSearchBase = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "user_dn_template":
				ldap_config.UserDnTemplate = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "tls_type":
				ldap_config.TlsType = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "certificate_authority":
				ldap_config.CA = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "certificate":
				ldap_config.Cert = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "key":
				ldap_config.Key = v
				log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
			case "insecure":
				insecure, err := strconv.ParseBool(v)
				if err == nil {
					ldap_config.Insecure = insecure
					log.Log.WithField("ldap_id", bucket).WithField(k, v).Debug("LDAP configuration from Consul")
				} else {
					log.Log.WithError(err).WithField(k, v).Warn("LDAP insecure parameter in consul has wrong format. Ignoring.")
				}
			default:
				log.Log.WithField(k, v).Warn("Ignoring LDAP parameter from Consul")
			}
		}
		conf.Ldap = append(conf.Ldap, ldap_config)
	}
}
