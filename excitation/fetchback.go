package excitation

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"appengine"
	"appengine/datastore"
	"appengine/memcache"
	"appengine/taskqueue"
	"appengine/urlfetch"
)

func roundTripTry_fetchback(addr Endpoint, key *datastore.Key, payload io.Reader, transport urlfetch.Transport, ctx appengine.Context) error {
	fr, err := http.NewRequest("POST", addr.Address, payload) // TODO type?
	if err != nil {
		ctx.Infof("create request: %s", err)
		return err
	}
	fr.Header.Add("X-Session-Id", addr.Sessionid)
	resp, err := transport.RoundTrip(fr)
	if err != nil {
		ctx.Infof("connect: %s", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		err = fmt.Errorf("Post failed, %v", resp.Status)
		ctx.Infof("%s", err)
		return err
	} else {
		ctx.Infof("RoundTrip %s", resp.Status)
	}
	if resp.ContentLength == 24 {
		tmpbuf := new(bytes.Buffer)
		_, err = tmpbuf.ReadFrom(resp.Body)
		if err != nil {
			ctx.Infof("reading from Body: %s", err)
			return err
		}
		if tmpbuf.String() == "@@@@CONNECTION CLOSE@@@@" {
			if key == nil {
				q := datastore.NewQuery("Endpoint").Filter("Sessionid =", addr.Sessionid).KeysOnly()
				t := q.Run(ctx)
				key, err = t.Next(addr)
				if err != nil {
					ctx.Infof("Delete error, getting key %s", err)
				}
			}
			err = datastore.Delete(ctx, key)
			return err
		}
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		ctx.Infof("reading from Body: %s", err)
		return err
	}
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
					ctx.Infof("Read %d bytes.\n", buf.Len())
				}
			} else {
				item = &memcache.Item{
					Key:   addr.Sessionid + ".buffer",
					Value: oneTask,
				}
				_ = memcache.Set(ctx, item)
			}
		}
		//ctx.Infof(buf.String())

	}

	return err
}

func process_fetchback(task Endpoint, key *datastore.Key, payload *bytes.Reader, ctx appengine.Context) error {
	tp := urlfetch.Transport{
		Context: ctx,
		// Despite the name, Transport.Deadline is really a timeout and
		// not an absolute deadline as used in the net package. In
		// other words it is a time.Duration, not a time.Time.
		Deadline: urlFetchTimeout,
	}
	flag := false
	for payload.Len() >= 998238 {
		tosend := io.LimitReader(payload, 998238)
		err := roundTripTry_fetchback(task, key, tosend, tp, ctx)
		if err != nil {
			flag = true
			ctx.Infof("%v", err)
		}
	}
	err := roundTripTry_fetchback(task, key, payload, tp, ctx)
	if err != nil {
		flag = true
		ctx.Infof("%v", err)
	}
	if flag {
		return fmt.Errorf("Error occurred when processing fetchback.")
	} else {
		return nil
	}
}

func handler_fetchback(w http.ResponseWriter, r *http.Request) {
	var record Endpoint
	var key *datastore.Key
	context := appengine.NewContext(r)

	//try to get more data?

	//verfity?
	
	if r.Method == "GET" {
		w.WriteHeader(200)
		fmt.Fprintf(w, "Warm up done")
		return
	}


	Sessionid := r.Header.Get("SESSIONID")
	payloadHash := r.Header.Get("PAYLOADHASH")
	num, err := strconv.Atoi(r.Header.Get("NUM"))
	if err != nil{
		num = 0
	}
	buf := bytes.NewBufferString("")
	if num == 0{
		item, err := memcache.Get(context, Sessionid+"."+payloadHash)
		if err != nil {
			w.WriteHeader(211)
			context.Errorf("Lost Packet in memcache %s, %s", Sessionid, payloadHash)
			fmt.Fprintf(w, "Lost Packet in memcache %s, %s", Sessionid, payloadHash)
			return
		}
		_, err = buf.Write(item.Value)
		if err != nil {
			w.WriteHeader(214)
			context.Errorf("%v", err)
			fmt.Fprintf(w, "Error when processing")
			return
		}
	} else {
		var counter int
		counter = 0
		for counter <= num {
			item, err := memcache.Get(context, Sessionid+"."+ payloadHash + strconv.Itoa(counter))
			if err != nil {
				w.WriteHeader(211)
				context.Errorf("Lost Packet in memcache %s, %s", Sessionid, payloadHash)
				fmt.Fprintf(w, "Lost Packet in memcache %s, %s", Sessionid, payloadHash)
				return
			}
			_, err = buf.Write(item.Value)
			if err != nil {
				w.WriteHeader(214)
				context.Errorf("%v", err)
				fmt.Fprintf(w, "Error when processing")
				return
			}
			counter++
		}
	}
	body := bytes.NewReader(buf.Bytes())
	item, err := memcache.Get(context, Sessionid+".Address")
	if err != nil {
		q := datastore.NewQuery("Endpoint").Filter("Sessionid =", Sessionid)
		t := q.Run(context)
		key, err = t.Next(&record)
		if err != nil {
			// what to do?
			w.WriteHeader(212)
			fmt.Fprintf(w, "")
			context.Infof("Not found Sessionid %s", Sessionid)
			fmt.Fprintf(w, "Not found Sessionid %s", Sessionid)
			return
		}
	} else {
		record = Endpoint{
			Address:   string(item.Value[:]),
			Sessionid: Sessionid,
		}
		key = nil
	}
	err = process_fetchback(record, key, body, context)
	if err != nil {
		w.WriteHeader(213)
		context.Errorf("Error when processing %v", err)
		fmt.Fprintf(w, "Error when processing")
		return
	} else {
		//fail?, server error? or dump
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "")
}