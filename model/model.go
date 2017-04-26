package model

import (
	"crypto/hmac"
	"crypto/sha256"
	"time"
)

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
