package model

import (
	"crypto/hmac"
	"crypto/sha256"
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
	LDAP_CONN_ERROR: "ldap_connection_error",
	RESTARTS: "restarts",
	HTTP_ABRUPT_TERM: "http_abrupt_termination",
	API_ABRUPT_TERM: "api_abrupt_termination",
	SIGTERM_SIGINT: "sigterm_sigint_received",
	SIGHUP: "sighup_received",
	UNKNOWN_SIG: "unknown_signal_received",
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
