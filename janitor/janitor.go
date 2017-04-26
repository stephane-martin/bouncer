package janitor

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/stephane-martin/nginx-auth-ldap/conf"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	"github.com/stephane-martin/nginx-auth-ldap/model"
)

type Janitor struct {
	Config       *conf.GlobalConfig
	Client       *redis.Client
	stop_chan    chan bool
}

func NewJanitor(config *conf.GlobalConfig, client *redis.Client) (janitor *Janitor) {
	return &Janitor{Config: config, Client: client}
}

func (j *Janitor) Start() {
	j.stop_chan = make(chan bool, 1)
	go j.background()
}

func (j *Janitor) background() {
	restart := true
	var tick time.Duration
	if j.Config.Redis.Expires <= 10 {
		tick = time.Second * 1
	} else {
		tick = time.Second * time.Duration(int64(float64(j.Config.Redis.Expires)/float64(10)))
	}
	log.Log.WithField("tick", tick).Debug("Janitor period")
	j.clean()
	for restart {
		select {
		case <-time.After(tick):
			j.clean()
		case <-j.stop_chan:
			restart = false
		}
	}
}

func (j *Janitor) Stop() {
	j.stop_chan <- true
	close(j.stop_chan)
}

func (j *Janitor) clean() {
	log.Log.Debug("Janitor: wake up to clean old records in Redis")
	limit := strconv.FormatInt(time.Now().UnixNano()-(j.Config.Redis.Expires*1000000000), 10)
	for _, t := range model.ResultTypes {
		sset := fmt.Sprintf("nginx-auth-ldap-sset-%d", t)
		result, err := j.Client.ZRemRangeByScore(sset, "-inf", limit).Result()
		if err != nil {
			log.Log.WithError(err).Error("Janitor: error deleting old entries in Redis")
			return
		}
		log.Log.WithField("nb", result).WithField("sorted_set", sset).Debug("Janitor: deleted old entries")
	}

}
