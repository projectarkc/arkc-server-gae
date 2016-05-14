package excitation

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
	"log"

	"appengine"
	"appengine/datastore"
	"appengine/memcache"
	"appengine/taskqueue"
	"appengine/urlfetch"
)

func roundTripTry(addr *Endpoint, key *datastore.Key, transport urlfetch.Transport, ctx appengine.Context) (io.Reader, bool, error) {
	// TODO: What to send here?
	fr, err := http.NewRequest("POST", addr.Address, bytes.NewReader([]byte("")))
	if err != nil {
		ctx.Infof("create request: %s", err)
		return nil, false, err
	}
	fr.Header.Add("X-Session-Id", addr.Sessionid)
	resp, err := transport.RoundTrip(fr)
	if err != nil {
		ctx.Infof("connect: %s", err)
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.ContentLength == 24 {
		tmpbuf := new(bytes.Buffer)
		tmpbuf.ReadFrom(resp.Body)
		if tmpbuf.String() == "@@@@CONNECTION CLOSE@@@@" {
			err := datastore.Delete(ctx, key)
			return nil, false, err
			// TODO: take further action?
		}
	}
	buf := new(bytes.Buffer)
	result := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.Len() > 0 {
		var bufContents []byte
		item, err := memcache.Get(ctx, addr.Sessionid+".buffer")
		if err == nil {
			bufContents = append(item.Value[:], buf.Bytes()[:]...)
		} else {
			bufContents = buf.Bytes()
		}
		tasks := bytes.Split(bufContents, []byte(SPLIT))
		for i, oneTask := range tasks {
			if i < len(tasks)-1 {
				log.Printf("%d", len(tasks))
				if len(oneTask) == 14 {
					continue
				} // message to close conn
				t := &taskqueue.Task{
					Path:    "/fetchfrom/",
					Method:  "POST",
					Header:  map[string][]string{"SESSIONID": {addr.Sessionid}},
					Payload: oneTask,
				}
				_, err = taskqueue.Add(ctx, t, "fetchfrom1")
				if err == nil {
					_, err = result.Write([]byte(fmt.Sprintf("Read %d bytes.\n", buf.Len())))
				}
			} else {
				item = &memcache.Item{
					Key:   addr.Sessionid + ".buffer",
					Value: oneTask,
				}
				_ = memcache.Set(ctx, item)
			}
		}
		//log.Printf(buf.String())
		return result, true, err
	} else {
		return result, false, err
	}

}

func getstatus(ctx appengine.Context, Id string) (*Endpoint, *datastore.Key) {
	//return a list of endpoints to connect, after checking if it had been checked in the interval
	var record Endpoint
	q := datastore.NewQuery("Endpoint").Filter("Sessionid = ", Id)
	t := q.Run(ctx)
	key, err := t.Next(&record)
	if err != nil {
		return nil, nil
	} else {
		return &record, key
	}
}

func processendpoints(task *Endpoint, key *datastore.Key, ctx appengine.Context) (string, bool, error) {
	tp := urlfetch.Transport{
		Context: ctx,
		// Despite the name, Transport.Deadline is really a timeout and
		// not an absolute deadline as used in the net package. In
		// other words it is a time.Duration, not a time.Time.
		Deadline: urlFetchTimeout,
	}
	response := new(bytes.Buffer)

	result, dataRetr, err := roundTripTry(task, key, tp, ctx)
	if err == nil {
		_, err = response.ReadFrom(result)
		return response.String(), dataRetr, nil
	} else {
		return "", false, err
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	context := appengine.NewContext(r)

	if r.Method == "GET" {
		w.WriteHeader(200)
		fmt.Fprintf(w, "Excitation ready to use")
		return
	}

	Sessionid := r.Header.Get("SESSIONID")
	task, key := getstatus(context, Sessionid)
	if task == nil {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Non-existing connection.\n")
		return
	}
	var count uint64
	var delay float64
	delay = initPollInterval
	count = 0
	startTime := time.Now()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Processing connection.\n")
	for true {
		reply, instant, err := processendpoints(task, key, context)
		if err != nil {
			count += 1
			if count >= 10 {
				_ = datastore.Delete(context, key)
				fmt.Fprintf(w, "Delete expired endpoint.\n")
				return
			}
		}
		fmt.Fprintf(w, reply)
		// check timeout
		tNow := time.Now()
		if tNow.Sub(startTime) > 570*time.Second {
			break
		}
		// wait
		if !instant {
			delay = delay * pollIntervalMultiplier
			if time.Duration(delay)*time.Millisecond < maxPollInterval {
				time.Sleep(time.Duration(delay) * time.Millisecond)
			} else {
				time.Sleep(maxPollInterval)
			}
		} else {
			delay = initPollInterval
		}
	}
	t := &taskqueue.Task{
		Path:   "/excite/",
		Method: "POST",
		Header: map[string][]string{"SESSIONID": {Sessionid}},
	}
	_, err := taskqueue.Add(context, t, "excitation")
	if err != nil {
		log.Printf("ADD FAIL")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return
}




func init() {
	http.HandleFunc("/excite/", handler)
	http.HandleFunc("/excite", handler)
	http.HandleFunc("/excitation/", handler)
	http.HandleFunc("/addconn/", handler_addconn)
	http.HandleFunc("/addconn", handler_addconn)
	http.HandleFunc("/fetchback/", handler_fetchback)
	http.HandleFunc("/fetchback", handler_fetchback)
}