package stats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/hashicorp/errwrap"
	"github.com/stephane-martin/nginx-auth-ldap/model"
)

const TOTAL_REQUESTS = "nginx-auth-ldap-nb-total-requests"
const SET_REQUESTS_TPL = "nginx-auth-ldap-sset-%d"

type Measurement struct {
	Period        string `json:"period"`
	Success       int64  `json:"success"`
	CachedSuccess int64  `json:"cache_success"`
	Fail          int64  `json:"fail"`
	Invalid       int64  `json:"invalid"`
	OpError       int64  `json:"op_error"`
	NoAuth        int64  `json:"no_auth"`
}

func (m *Measurement) Set(r model.Result, val int64) {
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

type Measurements struct {
	A []interface{}
}

func (m *Measurements) Json() ([]byte, error) {
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

func (m *Measurements) Append(x interface{}) {
	m.A = append(m.A, x)
}

func NewMeasurements() *Measurements {
	var m Measurements
	m.A = []interface{}{}
	return &m
}

func GetRange(now int64, nb_seconds int64) redis.ZRangeBy {
	return redis.ZRangeBy{Min: strconv.FormatInt(now-(nb_seconds*1000000000), 10), Max: strconv.FormatInt(now, 10)}
}

type Stats struct {
	client *redis.Client
}

func NewStats(c *redis.Client) *Stats {
	return &Stats{client: c}
}

func (s *Stats) Store(e *model.Event) error {
	set := fmt.Sprintf(SET_REQUESTS_TPL, e.Result)
	score := float64(e.Timestamp)
	value, err := json.Marshal(*e)
	if err == nil {
		pipe := s.client.TxPipeline()
		pipe.ZAdd(set, redis.Z{Score: score, Member: value})
		pipe.HIncrBy(TOTAL_REQUESTS, strconv.FormatInt(int64(e.Result), 10), 1)
		_, err = pipe.Exec()
		if err != nil {
			return errwrap.Wrapf("Error writing an event to Redis: {{err}}", err)
		}
	} else {
		return errwrap.Wrapf("Error marshalling an event to JSON: {{err}}", err)
	}
	return nil
}

func (s *Stats) GetMeasurementLastSeconds(now int64, nb_seconds int64) (*Measurement, error) {
	r := GetRange(now, nb_seconds)
	measurement := Measurement{}
	for _, t := range model.ResultTypes {
		sset := fmt.Sprintf(SET_REQUESTS_TPL, t)
		result, err := s.client.ZCount(sset, r.Min, r.Max).Result()
		if err != nil {
			return nil, errwrap.Wrapf("Error querying history in Redis: {{err}}", err)
		}
		measurement.Set(t, result)
	}
	return &measurement, nil
}

func (s *Stats) GetMeasurements(all_ranges map[string]int64) (*Measurements, error) {
	now := time.Now().UnixNano()
	measurements := NewMeasurements()
	for period_name, seconds := range all_ranges {
		measurement, err := s.GetMeasurementLastSeconds(now, seconds)
		if err != nil {
			return nil, err
		}
		measurement.Period = period_name
		measurements.Append(measurement)
	}

	measurement := Measurement{Period: "all"}
	m, err := s.client.HGetAll(TOTAL_REQUESTS).Result()
	if err != nil {
		return nil, err
	}
	for k, v := range m {
		t, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			return nil, err
		}
		val, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, err
		}
		measurement.Set(model.Result(t), val)
	}
	measurements.Append(measurement)

	return measurements, nil
}
