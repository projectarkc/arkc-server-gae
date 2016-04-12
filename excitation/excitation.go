// A web app for Google App Engine that proxies HTTP requests and responses to a
// Tor relay running meek-server.
package excitation

import (
	"io"
	"net/http"
	"time"
	//"bufio"
	"log"
	"bytes"
	"fmt"

	"appengine"
	"appengine/urlfetch"
	"appengine/taskqueue"
	"appengine/datastore"
	"appengine/memcache"
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

func roundTripTry(addr Endpoint, key *datastore.Key, transport urlfetch.Transport, ctx appengine.Context) (io.Reader, error) {
	// TODO: What to send here?
	fr, err := http.NewRequest("POST", addr.Address, bytes.NewReader([]byte("")))
	if err != nil {
		ctx.Errorf("create request: %s", err)
		return nil, err
	}
	fr.Header.Add("X-Session-Id", addr.Sessionid)
	resp, err := transport.RoundTrip(fr)
	if err != nil {
		ctx.Errorf("connect: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength == 24 {
		tmpbuf := new(bytes.Buffer)
		tmpbuf.ReadFrom(resp.Body)
		if tmpbuf.String() == "@@@@CONNECTION CLOSE@@@@" {
			err := datastore.Delete(ctx, key)
			return nil, err
		} 
	}
	buf := new(bytes.Buffer)
	result := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.Len() > 0 {
		log.Printf(buf.String())
		t := &taskqueue.Task {
			Path:		"/fetchfrom/",
			Method:		"POST",
			Header:		map[string][]string{"SESSIONID": {addr.Sessionid}},
			Payload:	buf.Bytes(),
		}
    	_, err = taskqueue.Add(ctx, t, "fetchfrom1")
    	if err==nil {
    		_, err = result.Write([]byte(fmt.Sprintf("Read %d bytes.\n", buf.Len())))
    	}
    }
    return result, err
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

func processendpoints(tasks []Endpoint, keys []*datastore.Key, ctx appengine.Context) string {
	tp := urlfetch.Transport{
			Context: ctx,
			// Despite the name, Transport.Deadline is really a timeout and
			// not an absolute deadline as used in the net package. In
			// other words it is a time.Duration, not a time.Time.
			Deadline: urlFetchTimeout,
		}
	response := new(bytes.Buffer)
	for i, clientaddr := range tasks {
		result, err := roundTripTry(clientaddr, keys[i], tp, ctx)
		if err == nil {
			_, err = response.ReadFrom(result)
		}
	}
	return response.String()
}

func handler(w http.ResponseWriter, r *http.Request) {
	context := appengine.NewContext(r)
	tasks, keys := getstatus(context)
	var count uint64
	count = 0
	if len(tasks) > 0 {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Processing %d connections.\n", len(tasks))
		//do the URLfetches and create tasks
		fmt.Fprintf(w, processendpoints(tasks, keys, context))
	} else {
		//http.Error(w, "Error when processing", http.StatusInternalServerError)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Nothing to process")
		count, _= memcache.Increment(context, "excite.count", 1, 0)
	}
	if count < 1000 {
		t := taskqueue.NewPOSTTask("/excite/", nil)
		//t.Delay = SPECIFY TIME WITH MEEK
    	log.Printf("ADDING")
    	_, err := taskqueue.Add(context, t, "excitation")
    	if err != nil {
        	log.Printf("ADD FAIL")
        	http.Error(w, err.Error(), http.StatusInternalServerError)
    	}
	} else {
		memcache.Delete(context, "excite.count")
	}

    return
}
	

func init() {
	http.HandleFunc("/", handler)
}
