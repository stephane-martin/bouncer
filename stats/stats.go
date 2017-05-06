package stats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/log"
	"github.com/stephane-martin/nginx-auth-ldap/model"
)

const TOTAL_REQUESTS = "nginx-auth-ldap-nb-total-requests"
const SET_REQUESTS_TPL = "nginx-auth-ldap-sset-%d"
const COUNTER_TPL = "nginx-auth-ldap-counter-%s"
const NOTIFICATIONS_REDIS_CHAN = "nginx-auth-ldap-notifications"

type HitsMeasure struct {
	Period        string `json:"period"`
	Success       int64  `json:"success"`
	CachedSuccess int64  `json:"cache_success"`
	Fail          int64  `json:"fail"`
	Invalid       int64  `json:"invalid"`
	OpError       int64  `json:"op_error"`
	NoAuth        int64  `json:"no_auth"`
}

func (m *HitsMeasure) Set(r model.Result, val int64) {
	switch r {
	case model.SUCCESS_AUTH:
		m.Success = val
	case model.SUCCESS_AUTH_CACHE:
		m.CachedSuccess = val
	case model.FAIL_AUTH:
		m.Fail = val
	case model.INVALID_REQUEST:
		m.Invalid = val
	case model.OP_ERROR:
		m.OpError = val
	case model.NO_AUTH:
		m.NoAuth = val
	default:
	}
}

type PackOfMeasures struct {
	A []interface{}
}

func (m *PackOfMeasures) Json() ([]byte, error) {
	s, err := json.Marshal(m.A)
	if err != nil {
		return nil, errwrap.Wrapf("Error marshalling measurements to JSON: {{err}}", err)
	}
	var buf bytes.Buffer
	err = json.Indent(&buf, s, "", "  ")
	if err != nil {
		return nil, errwrap.Wrapf("Error indenting JSON: {{err}}", err)
	}
	return buf.Bytes(), nil
}

func (m *PackOfMeasures) Append(x interface{}) {
	m.A = append(m.A, x)
}

func NewPack() *PackOfMeasures {
	var m PackOfMeasures
	m.A = []interface{}{}
	return &m
}

func GetRange(from int64, to int64) redis.ZRangeBy {
	return redis.ZRangeBy{Min: strconv.FormatInt(from, 10), Max: strconv.FormatInt(to, 10)}
}

type Counter struct {
	Client *redis.Client
	Name   string
}

func (c *Counter) Incr() error {
	if c.Client == nil {
		return nil
	}
	name := fmt.Sprintf(COUNTER_TPL, c.Name)
	return c.Client.Incr(name).Err()
}

func (c *Counter) Val() (string, int64, error) {
	if c.Client == nil {
		return "", 0, fmt.Errorf("No Redis client")
	}
	name := fmt.Sprintf(COUNTER_TPL, c.Name)
	s, err := c.Client.Get(name).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			return c.Name, 0, nil
		}
		return "", 0, err
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return "", 0, err
	}
	return c.Name, v, nil
}

type StatsManager struct {
	Client   *redis.Client
	Counters map[string]*Counter
}

func NewStatsManager(c *redis.Client) *StatsManager {
	return &StatsManager{Client: c, Counters: map[string]*Counter{}}
}

func (s *StatsManager) RegCounter(i model.CounterID) {
	s.Counters[model.CounterNames[i]] = &Counter{Client: s.Client, Name: model.CounterNames[i]}
}

func (s *StatsManager) Counter(i model.CounterID) *Counter {
	return s.Counters[model.CounterNames[i]]
}

func (s *StatsManager) Close() {
	if s.Client != nil {
		s.Client.Close()
	}
}

func (s *StatsManager) Store(e *model.RequestEvent) error {
	if s.Client == nil {
		return nil
	}
	set := fmt.Sprintf(SET_REQUESTS_TPL, e.Result)
	score := float64(e.Timestamp.UnixNano())
	value, err := json.Marshal(*e)
	if err == nil {
		pipe := s.Client.TxPipeline()
		pipe.ZAdd(set, redis.Z{Score: score, Member: value})
		pipe.HIncrBy(TOTAL_REQUESTS, strconv.FormatInt(int64(e.Result), 10), 1)
		pipe.Publish(NOTIFICATIONS_REDIS_CHAN, string(value))
		_, err = pipe.Exec()
		if err != nil {
			return errwrap.Wrapf("Error writing an event to Redis: {{err}}", err)
		}
	} else {
		return errwrap.Wrapf("Error marshalling an event to JSON: {{err}}", err)
	}
	return nil
}

func (s *StatsManager) GetLogs(from time.Time, to time.Time) (map[model.Result](*model.PackOfEvents), error) {
	pipe := s.Client.TxPipeline()
	cmds := map[model.Result]*redis.StringSliceCmd{}
	for _, t := range model.ResultTypes {
		sset := fmt.Sprintf(SET_REQUESTS_TPL, t)
		r := redis.ZRangeBy{Min: strconv.FormatInt(from.UnixNano(), 10), Max: strconv.FormatInt(to.UnixNano(), 10)}
		cmds[t] = pipe.ZRangeByScore(sset, r)
	}
	_, err := pipe.Exec()
	if err != nil {
		return nil, err
	}
	packs_of_events := map[model.Result](*model.PackOfEvents){}
	for _, t := range model.ResultTypes {
		packs_of_events[t] = &(model.PackOfEvents{})
		pack := packs_of_events[t]
		cmd := cmds[t]
		for _, event_s := range cmd.Val() {
			e := model.RequestEvent{}
			err := json.Unmarshal([]byte(event_s), &e)
			if err != nil {
				log.Log.WithError(err).WithField("event", event_s).Warn("Error decoding event from Redis")
			} else {
				*pack = append(*pack, &e)
			}
		}
		sort.Sort(*pack)
	}
	return packs_of_events, nil
}

func (s *StatsManager) GetHitsForPeriod(from int64, to int64) (*HitsMeasure, error) {
	if s.Client == nil {
		return nil, fmt.Errorf("No Redis client")
	}
	r := GetRange(from, to)
	measurement := HitsMeasure{}
	pipe := s.Client.TxPipeline()
	m := map[model.Result]*redis.IntCmd{}
	for _, t := range model.ResultTypes {
		sset := fmt.Sprintf(SET_REQUESTS_TPL, t)
		m[t] = pipe.ZCount(sset, r.Min, r.Max)
	}
	_, err := pipe.Exec()
	if err != nil {
		return nil, errwrap.Wrapf("Error querying history in Redis: {{err}}", err)
	}
	for _, t := range model.ResultTypes {
		measurement.Set(t, m[t].Val())
	}
	return &measurement, nil
}

func (s *StatsManager) GetStats(all_ranges map[string]int64) (*PackOfMeasures, error) {
	if s.Client == nil {
		return nil, fmt.Errorf("No Redis client")
	}
	now := time.Now().UnixNano()

	// get number of recent requests
	measurements := NewPack()
	for period_name, seconds := range all_ranges {
		measurement, err := s.GetHitsForPeriod(now-(seconds*1000000000), now)
		if err != nil {
			return nil, errwrap.Wrapf("error getting the number of recent requests from Redis: {{err}}", err)
		}
		measurement.Period = period_name
		measurements.Append(measurement)
	}

	// get total number of requests
	measurement := HitsMeasure{Period: "all"}
	vals, err := s.Client.HGetAll(TOTAL_REQUESTS).Result()
	if err != nil {
		return nil, errwrap.Wrapf("error getting the total number of requests from Redis: {{err}}", err)
	}
	for k, v := range vals {
		t, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			return nil, errwrap.Wrapf("Improper format for total counter in Redis: {{err}}", err)
		}
		val, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, errwrap.Wrapf("Improper format for total counter in Redis: {{err}}", err)
		}
		measurement.Set(model.Result(t), val)
	}
	measurements.Append(measurement)

	// get other counters
	for _, c := range s.Counters {
		m := map[string]int64{}
		name, val, err := c.Val()
		if err != nil {
			return nil, errwrap.Wrapf("error getting counters from Redis: {{err}}", err)
		}
		m[name] = val
		measurements.Append(m)
	}

	return measurements, nil
}
