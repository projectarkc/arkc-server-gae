// A web app for Google App Engine that proxies HTTP requests and responses to a
// Tor relay running meek-server.
package excitation

import (
	"io"
	"net/http"
	"time"
	"bufio"
	//"log"
	"bytes"

	"appengine"
	"appengine/urlfetch"
)

const (
	// A timeout of 0 means to use the App Engine default (5 seconds).
	urlFetchTimeout = 20 * time.Second
)

var context appengine.Context
//A very bad hack
var forward string

type endpoint struct {
	address    string
	password   string
	sessionid  string
}

func roundTripTry(addr endpoint, transport urlfetch.Transport) error {
	// TODO: What to send here?
	fr, err := http.NewRequest("POST", addr.address, bytes.NewReader([]byte("")))
	if err != nil {
		context.Errorf("create request: %s", err)
		return err
	}
	fr.Header.Add("X-Session-Id", addr.sessionid)
	resp, err := transport.RoundTrip(fr)
	if err != nil {
		context.Errorf("connect: %s", err)
		return err
	}
	// TODO
}

func getstatus() ([]endpoint) {
	//return a list of endpoints to connect, after checking if it had been checked in the interval
}

func processendpoints(tasks []endpoint, tp urlfetch.Transport) io.Reader {
	
	for _, clientaddr := range tasks {
		err := roundTripTry(clientaddr, tp)
		if err != nil {
			// create response and add to return value
		}
		
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	context = appengine.NewContext(r)
	tasks := getstatus()

	if len(tasks) > 0 {
		//do the URLfetches and create tasks
		transport := urlfetch.Transport{
			Context: context,
			// Despite the name, Transport.Deadline is really a timeout and
			// not an absolute deadline as used in the net package. In
			// other words it is a time.Duration, not a time.Time.
			Deadline: urlFetchTimeout,
		}
		n, err := io.Copy(w, processendpoints(tasks, transport))
		if err != nil {
		context.Errorf("io.Copy after %d bytes: %s", n, err)
		} else {
			//write empty response
		}
	}
}
	

func init() {
	http.HandleFunc("/", handler)
}
