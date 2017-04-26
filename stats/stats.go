package stats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/hashicorp/errwrap"
)

const TOTAL_REQUESTS = "nginx-auth-ldap-nb-total-requests"
const SET_REQUESTS_TPL = "nginx-auth-ldap-sset-%d"

type Result uint8

const (
	SUCCESS_AUTH Result = iota
	SUCCESS_AUTH_CACHE
	FAIL_AUTH
	INVALID_REQUEST
	OP_ERROR
	NO_AUTH
)

var ResultTypes []Result = []Result{SUCCESS_AUTH, SUCCESS_AUTH_CACHE, FAIL_AUTH, INVALID_REQUEST, OP_ERROR, NO_AUTH}

type Measurement struct {
	Period        string `json:"period"`
	Success       int64  `json:"success"`
	CachedSuccess int64  `json:"cache_success"`
	Fail          int64  `json:"fail"`
	Invalid       int64  `json:"invalid"`
	OpError       int64  `json:"op_error"`
	NoAuth        int64  `json:"no_auth"`
}

func (m *Measurement) Set(r Result, val int64) {
	switch r {
	case SUCCESS_AUTH:
		m.Success = val
	case SUCCESS_AUTH_CACHE:
		m.CachedSuccess = val
	case FAIL_AUTH:
		m.Fail = val
	case INVALID_REQUEST:
		m.Invalid = val
	case OP_ERROR:
		m.OpError = val
	case NO_AUTH:
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

func GetMeasurementLastSeconds(now int64, nb_seconds int64, c *redis.Client) (*Measurement, error) {
	r := GetRange(now, nb_seconds)
	measurement := Measurement{}
	for _, t := range ResultTypes {
		sset := fmt.Sprintf(SET_REQUESTS_TPL, t)
		result, err := c.ZCount(sset, r.Min, r.Max).Result()
		if err != nil {
			return nil, errwrap.Wrapf("Error querying history in Redis: {{err}}", err)
		}
		measurement.Set(t, result)
	}
	return &measurement, nil
}

func GetMeasurements(all_ranges map[string]int64, c *redis.Client) (*Measurements, error) {
	now := time.Now().UnixNano()
	measurements := NewMeasurements()
	for period_name, seconds := range all_ranges {
		measurement, err := GetMeasurementLastSeconds(now, seconds, c)
		if err != nil {
			return nil, err
		}
		measurement.Period = period_name
		measurements.Append(measurement)
	}

	measurement := Measurement{Period: "all"}
	m, err := c.HGetAll(TOTAL_REQUESTS).Result()
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
		measurement.Set(Result(t), val)
	}
	measurements.Append(measurement)

	return measurements, nil
}
