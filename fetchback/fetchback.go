// A web app for Google App Engine that proxies HTTP requests and responses to a
// Tor relay running meek-server.
package fetchback

import (
	"io"
	"net/http"
	"time"
	//"bufio"
	"log"
	"fmt"
	"bytes"

	"appengine"
	"appengine/urlfetch"
	"appengine/taskqueue"
	"appengine/datastore"
	"appengine/memcache"
)

const (
	// A timeout of 0 means to use the App Engine default (5 seconds).
	urlFetchTimeout = 20 * time.Second
	SPLIT = "\x1b\x1c\x1f"
)

type Endpoint struct {
	Address    string
	Password   []byte
	IV         string // IV is also mainpassword
	Sessionid  string
	IDChar     string
}

func roundTripTry(addr Endpoint, key *datastore.Key, payload io.Reader, transport urlfetch.Transport, ctx appengine.Context) error {
	fr, err := http.NewRequest("POST", addr.Address, payload) // TODO type?
	if err != nil {
		ctx.Errorf("create request: %s", err)
		return err
	}
	fr.Header.Add("X-Session-Id", addr.Sessionid)
	resp, err := transport.RoundTrip(fr)
	log.Printf("RoundTrip")
	if err != nil {
		ctx.Errorf("connect: %s", err)
		return err
	}
	defer resp.Body.Close()
	if resp.ContentLength == 24 {
		tmpbuf := new(bytes.Buffer)
		_, err = tmpbuf.ReadFrom(resp.Body)
		if err != nil{
			ctx.Errorf("reading from Body: %s", err)
			return err
		}
		if tmpbuf.String() == "@@@@CONNECTION CLOSE@@@@" {
			if key == nil {
				q := datastore.NewQuery("Endpoint").Filter("Sessionid =", addr.Sessionid).KeysOnly()
				t := q.Run(ctx)
				key, err = t.Next(addr)
				if err != nil {
					log.Printf("Delete error, getting key %s", err)
				}
			}
			err = datastore.Delete(ctx, key)
			return err
		} 
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		ctx.Errorf("reading from Body: %s", err)
		return err
	}
	if buf.Len() > 0 {
		var bufContents []byte
		item, err := memcache.Get(ctx, addr.Sessionid + ".buffer")
		if err == nil {
			bufContents = append(item.Value[:], buf.Bytes()[:]...)
		} else {
			bufContents = buf.Bytes()
		}
		tasks := bytes.Split(bufContents, []byte(SPLIT))
		for i, oneTask := range tasks {
			if i < len(tasks) - 1 {
				if len(oneTask) == 14 { continue } // message to close conn
				t := &taskqueue.Task {
					Path:		"/fetchfrom/",
					Method:		"POST",
					Header:		map[string][]string{"SESSIONID": {addr.Sessionid}},
					Payload:	oneTask,
				}
    			_, err = taskqueue.Add(ctx, t, "fetchfrom1")
    			if err==nil {
    				log.Printf("Read %d bytes.\n", buf.Len())
    			}
			} else {
				item = &memcache.Item{
					Key:	addr.Sessionid + ".buffer",
					Value:	oneTask,
				}
				_ = memcache.Set(ctx, item)
			}
		}
		//log.Printf(buf.String())
		
    }
    
    return err
}

func process(task Endpoint, key *datastore.Key, payload *bytes.Reader, ctx appengine.Context) error {
	tp := urlfetch.Transport{
			Context: ctx,
			// Despite the name, Transport.Deadline is really a timeout and
			// not an absolute deadline as used in the net package. In
			// other words it is a time.Duration, not a time.Time.
			Deadline: urlFetchTimeout,
	}
	var err error
	// every segment should be 4096
	for payload.Len() > 4096 {
		tosend := io.LimitReader(payload, 4096)
		err = roundTripTry(task, key, tosend, tp, ctx)
	}
	err = roundTripTry(task, key, payload, tp, ctx)
	return err
}

func handler(w http.ResponseWriter, r *http.Request) {
	var record Endpoint
	var key *datastore.Key
	context := appengine.NewContext(r)
	
	//try to get more data?

	Sessionid := r.Header.Get("SESSIONID")
	payloadHash := r.Header.Get("PAYLOADHASH")
	item, err := memcache.Get(context, Sessionid + "." + payloadHash)
	if err!= nil {
		w.WriteHeader(211)
		context.Errorf("Lost Packet in memcache %s, %s", Sessionid, payloadHash)
		fmt.Fprintf(w, "Lost Packet in memcache %s, %s", Sessionid, payloadHash)
		return
	}
	body := bytes.NewReader(item.Value)
	item, err = memcache.Get(context, Sessionid + ".Address")
	if err!= nil {
		q := datastore.NewQuery("Endpoint").Filter("Sessionid =", Sessionid)
		t := q.Run(context)
		key, err = t.Next(&record)
		if err != nil {
			// what to do?
			w.WriteHeader(212)
    		fmt.Fprintf(w, "")
    		context.Errorf("Not found Sessionid %s", Sessionid)
			fmt.Fprintf(w, "Not found Sessionid %s", Sessionid)
			return
		}
	} else {
		record = Endpoint{
			Address:	string(item.Value[:]),
			Sessionid:	Sessionid,
		}
		key = nil
	}
	err = process(record, key, body, context)
	if err != nil {
		w.WriteHeader(213)
    	fmt.Fprintf(w, "Error when processing")
		return
	} else {
		//fail?, server error? or dump
	}
	w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "")
}
	

func init() {
	http.HandleFunc("/", handler)
}
