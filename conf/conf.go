package conf

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"

	"github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/errwrap"
	"github.com/spf13/viper"
	"github.com/stephane-martin/bouncer/consul"
	"github.com/stephane-martin/bouncer/log"
)

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

	if len(c.Cache.Secret) == 0 {
		c.Cache.SecretAsBytes = make([]byte, 32)
		_, err := rand.Read(c.Cache.SecretAsBytes)
		if err != nil {
			return errwrap.Wrapf("Error generating Cache.Secret: {{err}}", err)
		}
		log.Log.Info("Cache.Secret was not provided in configuration, so we generated one.")
	} else {
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(c.Cache.Secret)))
		_, err := base64.StdEncoding.Decode(dst, []byte(c.Cache.Secret))
		if err != nil {
			return errwrap.Wrapf("Error reading Cache.Secret: not base64 encoded", err)
		}
		if len(dst) < 32 {
			return fmt.Errorf("Cache.Secret is too short")
		}
		c.Cache.SecretAsBytes = dst[:32]
	}

	return nil
}

func sclose(c chan bool) {
	if c != nil {
		close(c)
	}
}

func Load(dirname, c_addr, c_prefix, c_token, c_dtctr string, notify_chan chan bool) (conf *GlobalConfig, stop_chan chan bool, err error) {

	// - we must close notify_chan in all cases, when we don't plan to write anything more to it
	// - if some error happens, the returned stop_chan must be nil
	// - we enforce that behaviour for error cases in the first defer

	defer func() {
		// sometimes viper panics... let's catch that
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
		}
		if err != nil {
			sclose(stop_chan)
			sclose(notify_chan)
			stop_chan = nil
			conf = nil
		}
	}()

	// we must close notify_chan in all cases
	v := viper.New()
	set_defaults(v)
	SetEnvMapping(v)
	v.SetConfigName("bouncer")

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
		switch err.(type) {
		default:
			err = errwrap.Wrapf("Error reading the configuration file", err)
			return
		case viper.ConfigFileNotFoundError:
			log.Log.WithError(err).Debug("No configuration file was found")
		}
	}

	var config_in_consul map[string]string
	var client *api.Client

	if len(c_addr) > 0 {
		// consul is used for configuration
		client, err = consul.NewClient(c_addr, c_token, c_dtctr)
		if err != nil {
			return
		}
		// responsability to close notify_chan is transfered to WatchTree
		config_in_consul, stop_chan, err = consul.WatchTree(client, c_prefix, notify_chan)
		if err != nil {
			return
		}
		ParseConfigFromConsul(v, c_prefix, config_in_consul)
	} else {
		// consul is not used: we won't notify anything
		sclose(notify_chan)
	}

	conf = New()
	err = v.Unmarshal(conf)
	if err != nil {
		err = errwrap.Wrapf("Error parsing configuration", err)
		return
	}

	if len(config_in_consul) > 0 {
		ParseLdapConfigFromConsul(conf, c_prefix, config_in_consul)
	}

	InjectDefaultLdapConfiguration(conf, &conf.Ldap)
	err = GetRsaKeys(conf)
	if err != nil {
		return
	}
	err = GetLoginTpl(conf)
	if err != nil {
		return
	}
	err = conf.Check()
	return
}

func GetLoginTpl(c *GlobalConfig) error {
	c.Http.LoginTemplateContent = strings.Trim(c.Http.LoginTemplateContent, "\r\n\t ")
	c.Http.LoginTemplatePath = strings.TrimSpace(c.Http.LoginTemplatePath)
	if len(c.Http.LoginTemplateContent) == 0 {
		if len(c.Http.LoginTemplatePath) > 0 {
			content, err := ioutil.ReadFile(c.Http.LoginTemplatePath)
			if err != nil {
				log.Log.WithError(err).WithField("filename", c.Http.LoginTemplatePath).Error("Error reading the login template file")
			} else {
				c.Http.LoginTemplateContent = strings.Trim(string(content), "\r\n\t ")
			}
		}
		if len(c.Http.LoginTemplateContent) == 0 {
			c.Http.LoginTemplateContent = LOGIN_TPL_C
		}
	}
	t := template.New("login")
	var err error
	c.Http.LoginTemplate, err = t.Parse(c.Http.LoginTemplateContent)
	return err
}

func GetRsaKeys(c *GlobalConfig) error {
	var err error
	c.Signature.PrivateKeyPath = strings.TrimSpace(c.Signature.PrivateKeyPath)
	c.Signature.PrivateKeyContent = strings.Trim(c.Signature.PrivateKeyContent, "\r\n\t ")

	if len(c.Signature.PrivateKeyContent) == 0 && len(c.Signature.PrivateKeyPath) == 0 {
		log.Log.Info("No private key is configured")
		return nil
	}

	if len(c.Signature.PrivateKeyPath) > 0 && len(c.Signature.PrivateKeyContent) == 0 {
		log.Log.WithField("private_key_path", c.Signature.PrivateKeyPath).Info("Reading private key from path")
		content, err := ioutil.ReadFile(c.Signature.PrivateKeyPath)
		if err != nil {
			return errwrap.Wrapf("Failed to read the private key from path: {{err}}", err)
		}
		c.Signature.PrivateKeyContent = string(content)
	}
	c.Signature.PrivateKeyContent = strings.Trim(c.Signature.PrivateKeyContent, "\r\n\t ")

	if len(c.Signature.PrivateKeyContent) == 0 {
		log.Log.Warn("The private key is empty. Not configured.")
		return nil
	}

	private_key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(c.Signature.PrivateKeyContent))
	if err != nil {
		return errwrap.Wrapf("Error parsing the private key: {{err}}", err)
	}

	log.Log.Info("Private key has been correctly configured")
	c.Signature.PrivateKey = private_key
	c.Signature.PublicKey = &private_key.PublicKey
	return nil

}

func ParseConfigFromConsul(vi *viper.Viper, prefix string, c map[string]string) {
	c_prefix := prefix + "/conf"

	for k, v := range c {
		if strings.HasPrefix(k, c_prefix) {
			k = strings.Replace(strings.Trim(k[len(c_prefix):], "/"), "/", ".", -1)
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
			k = strings.Replace(strings.Trim(k[len(l_prefix):], "/"), "/", ".", -1)
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
		gl := log.Log.WithField("ldap_id", bucket)
		for k, v := range m {
			l := gl.WithField(k, v)
			switch k {
			case "host":
				ldap_config.Host = v
				l.Debug("LDAP configuration from Consul")
			case "port":
				port, err := strconv.ParseInt(v, 10, 32)
				if err == nil {
					ldap_config.Port = uint32(port)
					l.Debug("LDAP configuration from Consul")
				} else {
					log.Log.WithError(err).WithField(k, v).Warn("LDAP port in consul has wrong format. Ignoring.")
				}
			case "auth_type":
				ldap_config.AuthType = v
				l.Debug("LDAP configuration from Consul")
			case "bind_dn":
				ldap_config.BindDn = v
				l.Debug("LDAP configuration from Consul")
			case "bind_password":
				ldap_config.BindPassword = v
				l.Debug("LDAP configuration from Consul")
			case "user_search_filter":
				ldap_config.UserSearchFilter = v
				l.Debug("LDAP configuration from Consul")
			case "user_search_base":
				ldap_config.UserSearchBase = v
				l.Debug("LDAP configuration from Consul")
			case "user_dn_template":
				ldap_config.UserDnTemplate = v
				l.Debug("LDAP configuration from Consul")
			case "username_attribute":
				ldap_config.UsernameAttribute = v
				l.Debug("LDAP configuration from Consul")
			case "mail_attribute":
				ldap_config.MailAttribute = v
				l.Debug("LDAP configuration from Consul")
			case "return_mail":
				ret, err := strconv.ParseBool(v)
				if err == nil {
					ldap_config.ReturnMail = ret
					l.Debug("LDAP configuration from Consul")
				} else {
					l.WithError(err).Warn("LDAP 'return_mail' parameter in consul has wrong format. Ignoring.")
				}
			case "tls_type":
				ldap_config.TlsType = v
				l.Debug("LDAP configuration from Consul")
			case "certificate_authority":
				ldap_config.CA = v
				l.Debug("LDAP configuration from Consul")
			case "certificate":
				ldap_config.Cert = v
				l.Debug("LDAP configuration from Consul")
			case "key":
				ldap_config.Key = v
				l.Debug("LDAP configuration from Consul")
			case "insecure":
				insecure, err := strconv.ParseBool(v)
				if err == nil {
					ldap_config.Insecure = insecure
					l.Debug("LDAP configuration from Consul")
				} else {
					l.WithError(err).Warn("LDAP 'insecure' parameter in consul has wrong format. Ignoring.")
				}
			default:
				l.Warn("Ignoring unknown LDAP parameter from Consul")
			}
		}
		conf.Ldap = append(conf.Ldap, ldap_config)
	}
}

func InjectDefaultLdapConfiguration(conf *GlobalConfig, ldap_servers *[]LdapConfig) {
	// inject defaults into LDAP configurations
	for i := range *ldap_servers {
		if (*ldap_servers)[i].Host == "" {
			(*ldap_servers)[i].Host = conf.DefaultLdap.Host
		}
		if (*ldap_servers)[i].Port == 0 {
			(*ldap_servers)[i].Port = conf.DefaultLdap.Port
		}
		if (*ldap_servers)[i].AuthType == "" {
			(*ldap_servers)[i].AuthType = conf.DefaultLdap.AuthType
		}
		if (*ldap_servers)[i].BindDn == "" {
			(*ldap_servers)[i].BindDn = conf.DefaultLdap.BindDn
		}
		if (*ldap_servers)[i].BindPassword == "" {
			(*ldap_servers)[i].BindPassword = conf.DefaultLdap.BindPassword
		}
		if (*ldap_servers)[i].UserSearchFilter == "" {
			(*ldap_servers)[i].UserSearchFilter = conf.DefaultLdap.UserSearchFilter
		}
		if (*ldap_servers)[i].UserSearchBase == "" {
			(*ldap_servers)[i].UserSearchBase = conf.DefaultLdap.UserSearchBase
		}

		if (*ldap_servers)[i].UserDnTemplate == "" {
			(*ldap_servers)[i].UserDnTemplate = conf.DefaultLdap.UserDnTemplate
		}

		if (*ldap_servers)[i].UsernameAttribute == "" {
			(*ldap_servers)[i].UsernameAttribute = conf.DefaultLdap.UsernameAttribute
		}

		if (*ldap_servers)[i].MailAttribute == "" {
			(*ldap_servers)[i].MailAttribute = conf.DefaultLdap.MailAttribute
		}

		if !(*ldap_servers)[i].ReturnMail {
			(*ldap_servers)[i].ReturnMail = conf.DefaultLdap.ReturnMail
		}

		if (*ldap_servers)[i].TlsType == "" {
			(*ldap_servers)[i].TlsType = conf.DefaultLdap.TlsType
		}
		if (*ldap_servers)[i].CA == "" {
			(*ldap_servers)[i].CA = conf.DefaultLdap.CA
		}
		if (*ldap_servers)[i].Cert == "" {
			(*ldap_servers)[i].Cert = conf.DefaultLdap.Cert
		}
		if (*ldap_servers)[i].Key == "" {
			(*ldap_servers)[i].Key = conf.DefaultLdap.Key
		}
		if !(*ldap_servers)[i].Insecure {
			(*ldap_servers)[i].Insecure = conf.DefaultLdap.Insecure
		}

	}
}

func NewDiscoveryLdap(c *GlobalConfig, c_addr, c_token, c_dtctr, c_tag, c_service string) (*DiscoveryLdap, error) {
	client, err := consul.NewClient(c_addr, c_token, c_dtctr)
	if err != nil {
		return nil, err
	}
	d := DiscoveryLdap{
		conf:    c,
		client:  client,
		service: c_service,
		tag:     c_tag,
		mu:      &sync.RWMutex{},
		servers: []LdapConfig{},
		stop:    nil,
		updates: nil,
	}
	return &d, nil
}

func (d *DiscoveryLdap) Watch() {
	d.updates = make(chan []consul.ServiceAddress, 100)
	d.stop = consul.WatchServices(d.client, d.service, d.tag, d.updates)
	wait_first := make(chan bool, 1)
	first := true
	go func() {
		for {
			servers := []LdapConfig{}
			updates, more := <-d.updates
			if first {
				close(wait_first)
				first = false
			}
			if !more {
				return
			}
			for _, update := range updates {
				server := LdapConfig{Host: update.Host, Port: uint32(update.Port)}
				servers = append(servers, server)
			}
			if len(servers) == 0 {
				log.Log.Warn("No LDAP server was discovered.")
			} else {
				InjectDefaultLdapConfiguration(d.conf, &servers)
				d.mu.Lock()
				d.servers = servers
				d.mu.Unlock()
			}
		}
	}()
	<-wait_first
}

func (d *DiscoveryLdap) StopWatch() {
	if d.stop != nil {
		close(d.stop)
	}
}

func (d *DiscoveryLdap) Get() []LdapConfig {
	servers := []LdapConfig{}
	d.mu.RLock()
	for _, server := range d.servers {
		servers = append(servers, LdapConfig(server))
	}
	d.mu.RUnlock()
	return servers
}
