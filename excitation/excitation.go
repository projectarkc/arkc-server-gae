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
		t := taskqueue.NewPOSTTask("/fetchfrom/", 
				map[string][]string{"Sessionid": {addr.Sessionid},
									"contents": {buf.String()}})
    	_, err = taskqueue.Add(ctx, t, "fetchfrom1")
    	if err!=nil {
    		_, err = result.Read([]byte(fmt.Sprintf("Read from %d\n", buf.Len())))
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
		result, err := roundTripTry(clientaddr, keys[i], tp, ctx)
		if err != nil {
			_, _ = response.ReadFrom(result)
		}
	}
	return response
}

func handler(w http.ResponseWriter, r *http.Request) {
	context := appengine.NewContext(r)
	tasks, keys := getstatus(context)
	var count uint64
	if len(tasks) > 0 {
		w.WriteHeader(http.StatusOK)
		//do the URLfetches and create tasks
		n, err := io.Copy(w, processendpoints(tasks, keys, context))
		fmt.Fprintf(w, "%d endpoints processed.", len(tasks))
		if err != nil {
			context.Errorf("io.Copy after %d bytes: %s", n, err)
		}
		count = 0
	} else {
		//http.Error(w, "Error when processing", http.StatusInternalServerError)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Nothing to process")
		count, _= memcache.Increment(context, "excite.count", 1, 0)
	}
	if count < 1000 {
		t := taskqueue.NewPOSTTask("/excite/", nil)
    	if _, err := taskqueue.Add(context, t, "excitation"); err != nil {
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
