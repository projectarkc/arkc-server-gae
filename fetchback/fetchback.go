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
	"appengine/taskqueue"
	"appengine/datastore"
)

const (
	// A timeout of 0 means to use the App Engine default (5 seconds).
	urlFetchTimeout = 20 * time.Second
)

type endpoint struct {
	address    string
	password   string
	iv         string
	sessionid  string
	idchar     string
}

func roundTripTry(addr endpoint, key *datastore.Key, payload io.Reader, transport urlfetch.Transport, ctx appengine.Context) error {
	// TODO: What to send here?
	fr, err := http.NewRequest("POST", addr.address, payload) // TODO type?
	if err != nil {
		ctx.Errorf("create request: %s", err)
		return err
	}
	fr.Header.Add("X-Session-Id", addr.sessionid)
	resp, err := transport.RoundTrip(fr)
	if err != nil {
		ctx.Errorf("connect: %s", err)
		return err
	}
	defer resp.Body.Close()
	if resp.ContentLength == 24 {
		tmpbuf := new(bytes.Buffer)
		tmpbuf.ReadFrom(resp.Body)
		if tmpbuf.String() == "@@@@CONNECTION CLOSE@@@@" {
			err := datastore.Delete(ctx, key)
			return err
		} 
	}
	var buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	t := taskqueue.NewPOSTTask("/fetchfrom/", 
				map[string][]string{"sessionid": {addr.sessionid},
									"contents": {buf.String()}})
    _, err := taskqueue.Add(ctx, t, "fetchfrom1")
    return err
}

func process(task endpoint, key *datastore.Key, payload io.Reader, ctx appengine.Context) error {
	tp := urlfetch.Transport{
			Context: ctx,
			// Despite the name, Transport.Deadline is really a timeout and
			// not an absolute deadline as used in the net package. In
			// other words it is a time.Duration, not a time.Time.
			Deadline: urlFetchTimeout,
	}
	response := bytes.NewBuffer([]byte(""))
	
	err := roundTripTry(task, key, payload, tp, ctx)
	if err != nil {
		// TODO create response and add to return value
	}
	return response
}

func handler(w http.ResponseWriter, r *http.Request) {
	context = appengine.NewContext(r)

	// TODO get destination as endpoint, body as io.Reader, key as datastore.Key
		
	//do the URLfetches and create tasks
		
	err := process(destination, key, body, context))
	if err != nil {
		//return 200
	} else {
		//fail?, server error? or dump
	}
	
}
	

func init() {
	http.HandleFunc("/", handler)
}
