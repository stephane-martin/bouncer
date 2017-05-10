package conf

import (
	"bytes"
	"crypto/rsa"
	"html/template"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/hashicorp/consul/api"
	"github.com/stephane-martin/nginx-auth-ldap/consul"
)

type GlobalConfig struct {
	Ldap        []LdapConfig    `mapstructure:"ldap" toml:"ldap"`
	DefaultLdap LdapConfig      `mapstructure:"defaultldap" toml:"defaultldap"`
	Http        HttpConfig      `mapstructure:"http" toml:"http"`
	Api         ApiConfig       `mapstructure:"api" toml:"api"`
	Cache       CacheConfig     `mapstructure:"cache" toml:"cache"`
	Redis       RedisConfig     `mapstructure:"redis" toml:"redis"`
	Signature   SignatureConfig `mapstructure:"signature" toml:"signature"`
}

type LdapConfig struct {
	Host              string `mapstructure:"host" toml:"host"`
	Port              uint32 `mapstructure:"port" toml:"port"`
	AuthType          string `mapstructure:"auth_type" toml:"auth_type"`
	BindDn            string `mapstructure:"bind_dn" toml:"bind_dn"`
	BindPassword      string `mapstructure:"bind_password" toml:"bind_password"`
	UserSearchFilter  string `mapstructure:"user_search_filter" toml:"user_search_filter"`
	UserSearchBase    string `mapstructure:"user_search_base" toml:"user_search_base"`
	UserDnTemplate    string `mapstructure:"user_dn_template" toml:"user_dn_template"`
	UsernameAttribute string `mapstructure:"username_attribute" toml:"username_attribute"`
	MailAttribute     string `mapstructure:"mail_attribute" toml:"mail_attribute"`
	ReturnMail        bool   `mapstructure:"return_mail" toml:"return_mail"`
	TlsType           string `mapstructure:"tls_type" toml:"tls_type"`
	CA                string `mapstructure:"certificate_authority" toml:"certificate_authority"`
	Cert              string `mapstructure:"certificate" toml:"certificate"`
	Key               string `mapstructure:"key" toml:"key"`
	Insecure          bool   `mapstructure:"insecure" toml:"insecure"`
}

func (l *LdapConfig) String() string {
	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	encoder.Encode(*l)
	return buf.String()
}

type ApiConfig struct {
	BindAddr string `mapstructure:"bind_addr" toml:"bind_addr"`
	Port     uint32 `mapstructure:"port" toml:"port"`
}

type HttpConfig struct {
	BindAddr             string             `mapstructure:"bind_addr" toml:"bind_addr"`
	Port                 uint32             `mapstructure:"port" toml:"port"`
	Realm                string             `mapstructure:"realm" toml:"realm"`
	AuthorizationHeader  string             `mapstructure:"authorization_header" toml:"authorization_header"`
	AuthenticateHeader   string             `mapstructure:"authenticate_header" toml:"authenticate_header"`
	OriginalUriHeader    string             `mapstructure:"original_uri_header" toml:"original_uri_header"`
	OriginalHostHeader   string             `mapstructure:"original_host_header" toml:"original_host_header"`
	OriginalServerHeader string             `mapstructure:"original_server_header" toml:"original_server_header"`
	OriginalPortHeader   string             `mapstructure:"original_port_header" toml:"original_port_header"`
	OriginalProtoHeader  string             `mapstructure:"original_proto_header" toml:"original_proto_header"`
	RealIPHeader         string             `mapstructure:"real_ip_header" toml:"real_ip_header"`
	RemoteUserHeader     string             `mapstructure:"remote_user_header" toml:"remote_user_header"`
	JwtHeader            string             `mapstructure:"jwt_header" toml:"jwt_header"`
	FailedAuthDelay      uint32             `mapstructure:"failed_auth_delay_seconds" toml:"failed_auth_delay_seconds"`
	ShutdownTimeout      uint32             `mapstructure:"shutdown_timeout_seconds" toml:"shutdown_timeout_seconds"`
	Https                bool               `mapstructure:"https" toml:"https"`
	Certificate          string             `mapstructure:"certificate" toml:"certificate"`
	Key                  string             `mapstructure:"key" toml:"key"`
	MaskPassword         bool               `mapstructure:"mask_password" toml:"mask_password"`
	LoginTemplatePath    string             `mapstructure:"login_tpl_path" toml:"login_tpl_path"`
	LoginTemplateContent string             `mapstructure:"login_tpl" toml:"-"`
	LoginTemplate        *template.Template `toml:"-"`
	ErrorMessage         string             `mapstructure:"error_message" toml:"error_message"`
}

type CacheConfig struct {
	Expires       time.Duration `mapstructure:"expires" toml:"expires"`
	Secret        string        `mapstructure:"secret" toml:"secret"`
	SecretAsBytes []byte        `toml:"-"`
	CookieName    string        `mapstructure:"cookie_name" toml:"cookie_name"`
	CookieHeader  string        `mapstructure:"cookie_header" toml:"cookie_header"`
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

type SignatureConfig struct {
	PrivateKeyPath string `mapstructure:"private_key_path" toml:"private_key_path"`
	//PublicKeyPath string `mapstructure:"public_key_path" toml:"public_key_path"`
	PrivateKeyContent string `mapstructure:"private_key_content" toml:"-"`
	//PublicKeyContent string `mapstructure:"public_key_content" toml:"-"`
	PrivateKey *rsa.PrivateKey `toml:"-"`
	PublicKey  *rsa.PublicKey  `toml:"-"`
}

type DiscoveryLdap struct {
	conf    *GlobalConfig
	client  *api.Client
	service string
	tag     string
	mu      *sync.RWMutex
	servers []LdapConfig
	stop    chan bool
	updates chan []consul.ServiceAddress
}
