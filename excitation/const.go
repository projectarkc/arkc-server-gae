package excitation

import(
	"time"
	"crypto/rsa"
)

const (
	// A timeout of 0 means to use the App Engine default (5 seconds).
	urlFetchTimeout        = 20 * time.Second
	SPLIT                  = "\x1b\x1c\x1b\x1c\x1f"
	pollIntervalMultiplier = 1.5
	initPollInterval       = 100
	// Maximum polling interval.
	maxPollInterval = 5 * time.Second
)

var serverpri *rsa.PrivateKey
var ready = false

type Endpoint struct {
	Address   string
	Password  []byte
	IV        string // IV is also mainpassword
	Sessionid string
	IDChar    string
}

type Client struct {
	Clientprisha1 string
	Clientpub     string
	Clientsha1    string
}

type Server struct {
	Public  string
	Private string
}

var reflectedHeaderFields = []string{
	"Content-Type",
	"X-Session-Id",
}