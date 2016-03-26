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

func roundTripTry(addr endpoint, key *datastore.Key, transport urlfetch.Transport, ctx appengine.Context) error {
	// TODO: What to send here?
	fr, err := http.NewRequest("POST", addr.address, bytes.NewReader([]byte("")))
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

func getstatus() ([]endpoint, *[]datastore.Key) {
	//return a list of endpoints to connect, after checking if it had been checked in the interval
	var records []endpoint
	q := datastore.NewQuery("endpoint")
	keys, err = q.GetAll(ctx, &records)
	if err != nil {
		return "", nil, "", "", "", err
	}
	return records, keys
}

func processendpoints(tasks []endpoint, keys *[]datastore.Key, ctx appengine.Context) io.Reader {
	tp := urlfetch.Transport{
			Context: ctx,
			// Despite the name, Transport.Deadline is really a timeout and
			// not an absolute deadline as used in the net package. In
			// other words it is a time.Duration, not a time.Time.
			Deadline: urlFetchTimeout,
		}
	response := bytes.NewBuffer([]byte(""))
	for i, clientaddr := range tasks {
		err := roundTripTry(clientaddr, keys[i], tp, ctx)
		if err != nil {
			// TODO create response and add to return value
		}
		
	}
	return response
}

func handler(w http.ResponseWriter, r *http.Request) {
	context = appengine.NewContext(r)
	tasks, keys := getstatus()

	if len(tasks) > 0 {
		//do the URLfetches and create tasks
		
		n, err := io.Copy(w, processendpoints(tasks, keys, context))
		if err != nil {
			context.Errorf("io.Copy after %d bytes: %s", n, err)
		} else {
        	w.WriteHeader(http.StatusOK)
        	fmt.Fprintf(w, "")
		}
	}
}
	

func init() {
	http.HandleFunc("/", handler)
}
