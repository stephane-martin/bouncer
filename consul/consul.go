package consul

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/log"
)

func copy_map(m map[string]string) map[string]string {
	c := map[string]string{}
	for k, v := range m {
		c[k] = v
	}
	return c
}

func NewClient(addr, token, datacenter string) (*api.Client, error) {

	config := *api.DefaultConfig()
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, "http://") {
		config.Scheme = "http"
		addr = addr[7:len(addr)]
	} else if strings.HasPrefix(addr, "https://") {
		config.Scheme = "https"
		addr = addr[8:len(addr)]
	} else {
		return nil, fmt.Errorf("consul addr must start with 'http://' or 'https://'")
	}
	config.Address = addr
	config.Token = strings.TrimSpace(token)
	config.Datacenter = strings.TrimSpace(datacenter)

	client, err := api.NewClient(&config)
	if err != nil {
		return nil, errwrap.Wrapf("Error creating the consul client: {{err}}", err)
	}
	return client, nil
}

type ServiceAddress struct {
	Host string
	Port int
}

func WatchServices(client *api.Client, service string, tag string, updates chan []ServiceAddress) (stop chan bool) {

	watch := func(idx uint64) uint64 {
		q := &api.QueryOptions{RequireConsistent: true, WaitIndex: idx, WaitTime: time.Duration(2) * time.Second}
		entries, meta, err := client.Health().Service(service, tag, true, q)
		if err != nil {
			log.Log.WithError(err).Error("Error fetching services from Consul")
			time.Sleep(time.Second)
			return 0	
		}
		if meta.LastIndex != idx {
			idx = meta.LastIndex
			log.Log.WithField("index", idx).Debug("Updated services from Consul")
			services := []ServiceAddress{}
			for _, entry := range entries {
				addr := entry.Service.Address
				if len(addr) == 0 {
					addr = entry.Node.Address
				}
				services = append(services, ServiceAddress{Host: addr, Port: entry.Service.Port})
				log.Log.WithField("host", addr).WithField("port", entry.Service.Port).Debug("Discovered LDAP")
			}
			updates <- services 
		}
		return idx
	}
	
	stop = make(chan bool, 1)
	go func() {
		defer close(updates)
		var idx uint64
		for {
			select {
			case <-stop:
				return
			default:
				idx = watch(idx)
			}
		}
	}()

	return stop
}

func WatchTree(client *api.Client, prefix string, notifications chan bool) (results map[string]string, stop chan bool, err error) {
	// it is our job to close notify when we won't write anymore to it
	if client == nil || len(prefix) == 0 {
		log.Log.Info("Not watching Consul for dynamic configuration")
		if notifications != nil {
			close(notifications)
		}
		return nil, nil, nil
	}
	log.Log.WithField("prefix", prefix).Debug("Getting configuration from Consul")

	var first_index uint64
	results, first_index, err = getTree(client, prefix, 0)
	if err != nil {
		if notifications != nil {
			close(notifications)
		}
		return nil, nil, err
	}

	previous_index := first_index
	previous_keyvalues := copy_map(results)

	watch := func() {
		results, index, err := getTree(client, prefix, previous_index)
		if err != nil {
			log.Log.WithError(err).Warn("Error reading configuration in Consul")
			time.Sleep(time.Second)
			return
		}

		is_equal := true

		if index == previous_index {
			return
		}

		if is_equal && len(results) != len(previous_keyvalues) {
			is_equal = false
		}

		if is_equal {
			for k, v := range results {
				last_v, present := previous_keyvalues[k]
				if !present {
					is_equal = false
					break
				}
				if v != last_v {
					is_equal = false
					break
				}
			}
		}

		if !is_equal {
			notifications <- true
			previous_index = index
			previous_keyvalues = results
		}
	}

	if notifications != nil {
		stop = make(chan bool, 1)
		go func() {
			defer close(notifications)
			for {
				select {
				case <-stop:
					return
				default:
					watch()
				}
			}
		}()
	}
	return results, stop, nil

}

func getTree(client *api.Client, prefix string, waitIndex uint64) (map[string]string, uint64, error) {
	q := &api.QueryOptions{RequireConsistent: true, WaitIndex: waitIndex, WaitTime: time.Duration(2) * time.Second}
	kvpairs, meta, err := client.KV().List(prefix, q)
	if err != nil {
		return nil, 0, errwrap.Wrapf("Error reading configuration in Consul: {{err}}", err)
	}
	if len(kvpairs) == 0 {
		return nil, meta.LastIndex, nil
	}
	results := map[string]string{}
	for _, v := range kvpairs {
		results[strings.TrimSpace(string(v.Key))] = strings.TrimSpace(string(v.Value))
	}
	return results, meta.LastIndex, nil
}
