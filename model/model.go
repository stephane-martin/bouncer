package model

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/errwrap"
	"github.com/satori/go.uuid"
	"github.com/stephane-martin/nginx-auth-ldap/log"
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
	SUCCESS_AUTH_NAL_COOKIE
)

var ResultTypes []Result = []Result{SUCCESS_AUTH, SUCCESS_AUTH_CACHE, FAIL_AUTH, INVALID_REQUEST, OP_ERROR, NO_AUTH, SUCCESS_AUTH_NAL_COOKIE}

type Identity struct {
	Username    string `json:"username"`
	UsernameOut string `json:"username_out"`
	Email       string `json:"email"`
}

type Token struct {
	Identity
	Password  string        `json:"password"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

type RequestEvent struct {
	Identity
	Password  string    `json:"-"`
	Host      string    `json:"host"`
	Uri       string    `json:"uri"`
	Port      string    `json:"port"`
	Proto     string    `json:"proto"`
	RetCode   int       `json:"retcode"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
	Result    Result    `json:"result"`
	ClientIP  string    `json:"client_ip"`
	Cookie    string    `json:"-"`
}

const EventStringFormat string = `Timestamp %s
Proto: %s
Host: %s
Port: %s
Uri: %s
Client IP: %s
Username: %s
Returned code: %d
Result: %d
Message: %s
`

func (e *RequestEvent) String() string {
	return fmt.Sprintf(EventStringFormat, e.Timestamp.Format(time.RFC3339), e.Proto, e.Host, e.Port, e.Uri, e.ClientIP, e.Username, e.RetCode, e.Result, e.Message)
}

func (e *RequestEvent) GenerateBackendJwt(key *rsa.PrivateKey, issuer string) (string, error) {
	now := time.Now()
	claims := &jwt.StandardClaims{
		IssuedAt:  now.Unix(),
		Subject:   e.UsernameOut,
		NotBefore: now.Unix(),
		Issuer:    issuer,
		Id:        uuid.NewV4().String(),
		Audience:  "backend-apps",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token_s, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return token_s, nil
}

func (e *RequestEvent) GenerateCookie(secret []byte, d time.Duration) (string, error) {
	if len(secret) < 32 {
		return "", fmt.Errorf("secret has less than 32 chars")
	}
	token := Token{
		Identity{
			Username:    e.Username,
			UsernameOut: e.UsernameOut,
			Email:       e.Email,
		},
		e.Password,
		time.Now(),
		d,
	}
	b, err := json.Marshal(token)
	if err != nil {
		return "", errwrap.Wrapf("Error generating token/json marshalling: {{err}}", err)
	}
	var secretb [32]byte
	copy(secretb[:], secret[:32])
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return "", errwrap.Wrapf("Error generating token/crypto random source: {{err}}", err)
	}
	encrypted := secretbox.Seal(nonce[:], b, &nonce, &secretb)
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func (e *RequestEvent) VerifyCookie(secret []byte) *Token {
	l := log.Log.WithField("fun", "VerifyCookie")
	if len(secret) < 32 {
		l.Warn("secret is too short")
		return nil
	}
	cookie := strings.TrimSpace(e.Cookie)
	if len(cookie) == 0 {
		l.Debug("No NAL Cookie")
		return nil
	}
	encrypted, err := base64.URLEncoding.DecodeString(cookie)
	if err != nil {
		l.Warn("NAL Cookie is not base64 encoded")
		return nil
	}
	var secretb [32]byte
	copy(secretb[:], secret[:32])
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open([]byte{}, encrypted[24:], &decryptNonce, &secretb)
	if !ok {
		l.Warn("Verification failed")
		return nil
	}
	token := Token{}
	err = json.Unmarshal(decrypted, &token)
	if err != nil {
		l.WithError(err).Warn("JSON unmarshaling failed")
		return nil
	}
	now := time.Now()
	if now.Before(token.Timestamp) {
		l.Warn("Invalid cookie creation timestamp")
		return nil
	}
	if now.Sub(token.Timestamp) > token.Duration {
		l.Debug("Expired NAL Cookie")
		return nil
	}
	return &token
}

type PackOfEvents []*RequestEvent

func (p PackOfEvents) Len() int {
	return len(p)
}
func (p PackOfEvents) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}
func (p PackOfEvents) Less(i, j int) bool {
	return p[i].Timestamp.Before(p[j].Timestamp)
}

func NewEmptyEvent() *RequestEvent {
	return &RequestEvent{Timestamp: time.Now()}
}

func (e *RequestEvent) Hmac(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(e.Username))
	mac.Write([]byte(":"))
	mac.Write([]byte(e.Password))
	return mac.Sum(nil)
}
