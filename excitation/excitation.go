// A web app for Google App Engine that proxies HTTP requests and responses to a
// Tor relay running meek-server.
package excitation

import (
	"io"
	"net/http"
	"time"
	//"bufio"
	//"log"
	"bytes"
	"fmt"

	"appengine"
	"appengine/urlfetch"
	"appengine/taskqueue"
	"appengine/datastore"
)

const (
	// A timeout of 0 means to use the App Engine default (5 seconds).
	urlFetchTimeout = 20 * time.Second
)

type Endpoint struct {
	Address    string
	Password   []byte
	IV         string // IV is also mainpassword
	Sessionid  string
	IDChar     string
}

func roundTripTry(addr Endpoint, key *datastore.Key, transport urlfetch.Transport, ctx appengine.Context) error {
	// TODO: What to send here?
	fr, err := http.NewRequest("POST", addr.Address, bytes.NewReader([]byte("")))
	if err != nil {
		ctx.Errorf("create request: %s", err)
		return err
	}
	fr.Header.Add("X-Session-Id", addr.Sessionid)
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
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	t := taskqueue.NewPOSTTask("/fetchfrom/", 
				map[string][]string{"Sessionid": {addr.Sessionid},
									"contents": {buf.String()}})
    _, err = taskqueue.Add(ctx, t, "fetchfrom1")
    return err
}

func getstatus(ctx appengine.Context) ([]Endpoint, []*datastore.Key) {
	//return a list of endpoints to connect, after checking if it had been checked in the interval
	var records []Endpoint
	q := datastore.NewQuery("Endpoint")
	keys, err := q.GetAll(ctx, &records)
	if err != nil {
		return nil, nil
	}
	return records, keys
}

func processendpoints(tasks []Endpoint, keys []*datastore.Key, ctx appengine.Context) io.Reader {
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
	context := appengine.NewContext(r)
	tasks, keys := getstatus(context)

	if len(tasks) > 0 {
		w.WriteHeader(http.StatusOK)
		//do the URLfetches and create tasks
		n, err := io.Copy(w, processendpoints(tasks, keys, context))
		if err != nil {
			context.Errorf("io.Copy after %d bytes: %s", n, err)
		}
		return
	} else {
		//http.Error(w, "Error when processing", http.StatusInternalServerError)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Nothing to process")
		return
	}
}
	

func init() {
	http.HandleFunc("/", handler)
}
