package model

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"
)

type CounterID uint8

const (
	LDAP_CONN_ERROR = iota
	RESTARTS
	HTTP_ABRUPT_TERM
	API_ABRUPT_TERM
	SIGTERM_SIGINT
	SIGHUP
	UNKNOWN_SIG
)

var CounterNames map[CounterID]string = map[CounterID]string{
	LDAP_CONN_ERROR:  "ldap_connection_error",
	RESTARTS:         "restarts",
	HTTP_ABRUPT_TERM: "http_abrupt_termination",
	API_ABRUPT_TERM:  "api_abrupt_termination",
	SIGTERM_SIGINT:   "sigterm_sigint_received",
	SIGHUP:           "sighup_received",
	UNKNOWN_SIG:      "unknown_signal_received",
}

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

type Event struct {
	Username  string `json:"username"`
	Password  string `json:"-"`
	Host      string `json:"host"`
	Uri       string `json:"uri"`
	Port      string `json:"port"`
	Proto     string `json:"proto"`
	RetCode   int    `json:"retcode"`
	Timestamp int64  `json:"timestamp,string"`
	Message   string `json:"message"`
	Result    Result `json:"result"`
}

const EventStringFormat string = `Timestamp %d
Proto: %s
Host: %s
Port: %s
Uri: %s
Username: %s
Returned code: %d
Result: %d
Message: %s
`

func (e *Event) String() string {
	return fmt.Sprintf(EventStringFormat, e.Timestamp, e.Proto, e.Host, e.Port, e.Uri, e.Username, e.RetCode, e.Result, e.Message)
}

type PackOfEvents []*Event

func (p PackOfEvents) Len() int {
	return len(p)
}
func (p PackOfEvents) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}
func (p PackOfEvents) Less(i, j int) bool {
	return p[i].Timestamp < p[j].Timestamp
}

func NewEmptyEvent() *Event {
	return &Event{Timestamp: time.Now().UnixNano()}
}

func (e *Event) Hmac(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(e.Username))
	mac.Write([]byte(":"))
	mac.Write([]byte(e.Password))
	return mac.Sum(nil)
}
