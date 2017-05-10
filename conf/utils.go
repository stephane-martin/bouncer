package conf

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis"
)

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
