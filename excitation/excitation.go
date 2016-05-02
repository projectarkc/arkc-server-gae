// A web app for Google App Engine that proxies HTTP requests and responses to a
// Tor relay running meek-server.
package excitation

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"log"

	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	mrand "math/rand"

	"appengine"
	"appengine/datastore"
	"appengine/memcache"
	"appengine/taskqueue"
	"appengine/urlfetch"
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

func roundTripTry_fetchback(addr Endpoint, key *datastore.Key, payload io.Reader, transport urlfetch.Transport, ctx appengine.Context) error {
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
		if err != nil {
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
					log.Printf("Read %d bytes.\n", buf.Len())
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
	var err error
	// every segment should be 4096
	for payload.Len() > 4096 {
		tosend := io.LimitReader(payload, 4096)
		err = roundTripTry_fetchback(task, key, tosend, tp, ctx)
	}
	err = roundTripTry_fetchback(task, key, payload, tp, ctx)
	return err
}

func handler_fetchback(w http.ResponseWriter, r *http.Request) {
	var record Endpoint
	var key *datastore.Key
	context := appengine.NewContext(r)

	//try to get more data?

	Sessionid := r.Header.Get("SESSIONID")
	payloadHash := r.Header.Get("PAYLOADHASH")
	num, err := strconv.Atoi(r.Header.Get("NUM"))
	if err != nil{
		num = 0
	}
	buf := new(bytes.Buffer)
	if num == 0{
		item, err := memcache.Get(context, Sessionid+"."+payloadHash)
		_, err = buf.Read(item.Value)
		if err != nil {
			w.WriteHeader(211)
			context.Errorf("Lost Packet in memcache %s, %s", Sessionid, payloadHash)
			fmt.Fprintf(w, "Lost Packet in memcache %s, %s", Sessionid, payloadHash)
			return
		}
	} else {
		var counter int
		counter = 0
		for counter <= num {
			item, err := memcache.Get(context, Sessionid+"."+ payloadHash + strconv.Itoa(counter))
			_, err = buf.Read(item.Value)
			if err != nil {
				w.WriteHeader(211)
				context.Errorf("Lost Packet in memcache %s, %s", Sessionid, payloadHash)
				fmt.Fprintf(w, "Lost Packet in memcache %s, %s", Sessionid, payloadHash)
				return
			}
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
			context.Errorf("Not found Sessionid %s", Sessionid)
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
		fmt.Fprintf(w, "Error when processing")
		return
	} else {
		//fail?, server error? or dump
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "")
}

func roundTripTry(addr *Endpoint, key *datastore.Key, transport urlfetch.Transport, ctx appengine.Context) (io.Reader, bool, error) {
	// TODO: What to send here?
	fr, err := http.NewRequest("POST", addr.Address, bytes.NewReader([]byte("")))
	if err != nil {
		ctx.Errorf("create request: %s", err)
		return nil, false, err
	}
	fr.Header.Add("X-Session-Id", addr.Sessionid)
	resp, err := transport.RoundTrip(fr)
	if err != nil {
		ctx.Errorf("connect: %s", err)
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

// Get the original client IP Address as a string. When using the standard
// net/http server, Request.RemoteAddr is a "host:port" string; however App
// Engine seems to use just "host". We check for both to be safe.
func getClientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// Make a copy of r, with the URL being changed to be relative to forwardURL,
// and including only the headers in reflectedHeaderFields.
func processRequest(forward string, payload io.Reader, Sessionid string) (*http.Request, error) {
	u, err := url.Parse(forward)
	if err != nil {
		return nil, err
	}
	// Append the requested path to the path in forwardURL, so that
	// forwardURL can be something like "https://example.com/reflect".
	//u.Path = pathJoin(u.Path, r.URL.Path)
	//log.Print("URL is " + u.String())
	c, err := http.NewRequest("POST", u.String(), payload)
	if err != nil {
		return nil, err
	}
	c.Header.Add("X-Session-Id", Sessionid)
	return c, nil
}

func loadserverkey(ctx appengine.Context) error {
	//load key from datastore or memcache
	var block *pem.Block
	if item, err := memcache.Get(ctx, "serverpri"); err != memcache.ErrCacheMiss {
		block, _ = pem.Decode(item.Value)
	} else {
		var record []Server
		q := datastore.NewQuery("Server").Limit(1)
		_, err = q.GetAll(ctx, &record)
		if err != nil || len(record) == 0 {
			ctx.Errorf("server key missing: %s", err)
			//return fmt.Errorf("Error when searching for server keys")

		}
		block, _ = pem.Decode([]byte(record[0].Private))
		item = &memcache.Item{
			Key:   "serverpri",
			Value: []byte(record[0].Private),
		}
		_ = memcache.Add(ctx, item)
	}
	serverpri, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	return nil
}

func getpreviousindex(mainpw []byte, number int, ctx appengine.Context) ([]byte, string, error) {
	var record []Endpoint

	// use memcache as buffer
	q := datastore.NewQuery("Endpoint").Filter("IV =", string(mainpw[:])).Order("IV").Order("IDChar")
	_, err := q.GetAll(ctx, &record)
	if err != nil {
		return nil, "", err
	}
	if len(record) >= number {
		return nil, "", fmt.Errorf("Already enough connections")
	} else {
		if len(record) != 0 {
			// method in doubt
			last, _ := strconv.Atoi(record[0].IDChar)
			for _, rec := range record {
				now, _ := strconv.Atoi(rec.IDChar)
				if now-last >= 2 {
					break
				}
				last = now
			}
			return []byte(""), strconv.Itoa(last + 1), nil
		} else {
			return []byte(""), "0", nil
		}
	}

}

func getauthstring(body *bufio.Reader, ctx appengine.Context) (string, io.Reader, string, string, string, string, error) {
	//return
	// URL to send, string
	// contents, io.Reader
	// clientid, string
	// Password, string
	// IV, string
	// IDChar, string
	// error
	var record Client

	sha1, _, err := body.ReadLine()
	if err != nil {

		return "", nil, "", "", "", "", err
	}

	url, _, err := body.ReadLine()
	if err != nil {
		return "", nil, "", "", "", "", err
	}
	mainpw, _, err := body.ReadLine()
	if err != nil {
		return "", nil, "", "", "", "", err
	}
	number, _, err := body.ReadLine()
	if err != nil {
		return "", nil, "", "", "", "", err
	}
	i, err := strconv.Atoi(string(number[:]))
	if err != nil {
		return "", nil, "", "", "", "", err
	}

	previousrecord, IDChar, err := getpreviousindex(mainpw, i, ctx)
	if err != nil {
		return "", nil, "", "", "", "", err
	}
	//try to load from memcache
	q := datastore.NewQuery("Client").
		Filter("Clientsha1 =", string(sha1[:]))
	t := q.Run(ctx)
	_, err = t.Next(&record)
	if err != nil {
		return "", nil, "", "", "", "", err
	}
	//ctx.Errorf("%s, %s, %s", record.Clientpub, record.Clientsha1, record.Clientprisha1)
	//write to memcache
	sessionpassword := make([]byte, 16)
	rand.Read(sessionpassword)

	//debug
	//sessionpassword = []byte("aaaaaaaaaaaaaaaa")
	pub_key, err := DecodePublicKey(record.Clientpub)
	rsaPub, ok := pub_key.(*rsa.PublicKey)
	if !ok || rsaPub == nil {
		return "", nil, "", "", "", "", fmt.Errorf("BAD key")
	}

	if !ready {
		err = loadserverkey(ctx)
		if err != nil {
			return "", nil, "", "", "", "", err
		}
		ready = true
	}
	hashed := sha256.Sum256(mainpw)
	part1, err := rsa.SignPKCS1v15(rand.Reader, serverpri, crypto.SHA256, hashed[:])
	if err != nil {
		return "", nil, "", "", "", "", err
	}
	part2, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, sessionpassword)
	if err != nil {
		return "", nil, "", "", "", "", err
	}

	contents := bytes.NewBuffer(part1)
	contents.WriteString("\r\n")
	contents.Write(part2)
	contents.WriteString("\r\n")
	contents.WriteString(IDChar)
	contents.WriteString("\r\n")
	contents.Write(previousrecord)
	contents.WriteString("\r\n")
	//contents.Write(mainpw)
	return string(url[:]), contents, string(sha1[:]), string(sessionpassword[:]), string(mainpw[:]), string(IDChar[:]), nil
}

func authverify(body *bufio.Reader, IDChar string, authstring string, IV string) error {
	//verify if the Password is correct
	value, _, err := body.ReadLine()
	if err != nil {
		return err
	}
	aescipher, err := aes.NewCipher([]byte(authstring))
	if err != nil {
		return err
	}
	stream := cipher.NewCFBDecrypter(aescipher, []byte(IV))
	stream.XORKeyStream(value, value)
	if bytes.Compare(bytes.TrimRight(value, "\x01"), []byte("2AUTHENTICATED"+IDChar)) != 0 {
		return fmt.Errorf("AUTH FAIL %s\n", value)
	} else {
		//TODO throw the rest to task queue?
		return nil
	}

}

func storestring(ctx appengine.Context, url string, Sessionid string, authstring string, IV string, IDChar string) (io.Reader, error) {
	//use Datastore and Memcache to store the string
	//return
	// current status, io.Reader
	// error
	var items []*memcache.Item
	record := Endpoint{
		Address:   url,
		Password:  []byte(authstring),
		IV:        IV,
		Sessionid: Sessionid,
		IDChar:    IDChar,
	}
	key := datastore.NewIncompleteKey(ctx, "Endpoint", nil)
	_, err := datastore.Put(ctx, key, &record)
	if err != nil {
		return nil, fmt.Errorf("%s, %s, %s, %s", url, IV, Sessionid, IDChar) //err
	}
	items = append(items,
		&memcache.Item{
			Key:   Sessionid + ".Address",
			Value: []byte(url),
		},
		&memcache.Item{
			Key:   Sessionid + ".Password",
			Value: []byte(authstring),
		},
		&memcache.Item{
			Key:   Sessionid + ".IV",
			Value: []byte(IV),
		},
		&memcache.Item{
			Key:   Sessionid + ".IDChar",
			Value: []byte(IDChar),
		},
	)
	_ = memcache.AddMulti(ctx, items)
	// TODO get status
	return bytes.NewBuffer([]byte("")), nil

}

func RandomString(strlen int) []byte {
	mrand.Seed(time.Now().UTC().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = chars[mrand.Intn(len(chars))]
	}
	return result
}

func handler_addconn(w http.ResponseWriter, r *http.Request) {
	context := appengine.NewContext(r)
	forward, payload, _, passwd, IV, IDChar, err := getauthstring(bufio.NewReader(r.Body), context)
	//context.Errorf("%s, %s, %s, %s, %s, %s", forward, payload, clientid, passwd, IV, IDChar)
	if err != nil {
		context.Errorf("parseRequest: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, err.Error())
		return
	}
	Sessionid := string(RandomString(16)[:])
	fr, err := processRequest(forward, payload, Sessionid)
	if err != nil {
		context.Errorf("processRequest: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, err.Error())
		return
	}
	// Use urlfetch.Transport directly instead of urlfetch.Client because we
	// want only a single HTTP transaction, not following redirects.
	transport := urlfetch.Transport{
		Context: context,
		// Despite the name, Transport.Deadline is really a timeout and
		// not an absolute deadline as used in the net package. In
		// other words it is a time.Duration, not a time.Time.
		Deadline: urlFetchTimeout,
	}
	resp, err := transport.RoundTrip(fr)
	if err != nil {
		context.Errorf("RoundTrip: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		context.Errorf("URL Fetch error, code=%d", resp.StatusCode)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "URL Fetch error, code=%d", resp.StatusCode)
		return
	}
	err = authverify(bufio.NewReader(resp.Body), IDChar, passwd, IV)
	if err != nil {
		failResp := bytes.NewReader([]byte("@@@@CONNECTION CLOSE@@@@"))
		frCloseconn, err := processRequest(forward, failResp, Sessionid)
		_, _ = transport.RoundTrip(frCloseconn)
		context.Errorf("Authentication: %s", err)
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, err.Error())
		return
	}
	reply, err := storestring(context, forward, Sessionid, passwd, IV, IDChar)
	if err != nil {
		context.Errorf("Saving: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t := &taskqueue.Task{
		Path:   "/excite/",
		Method: "POST",
		Header: map[string][]string{"SESSIONID": {Sessionid}},
	}
	_, _ = taskqueue.Add(context, t, "excitation")
	w.Header().Add("X-Session-Id", Sessionid)
	w.WriteHeader(resp.StatusCode)
	n, err := io.Copy(w, reply)
	if err != nil {
		context.Errorf("io.Copy after %d bytes: %s", n, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	context := appengine.NewContext(r)
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


/************************************************************
Below adapted from https://github.com/ianmcmahon/encoding_ssh
************************************************************/

func readLength(data []byte) ([]byte, uint32, error) {
	l_buf := data[0:4]

	buf := bytes.NewBuffer(l_buf)

	var length uint32

	err := binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return nil, 0, err
	}

	return data[4:], length, nil
}

func readBigInt(data []byte, length uint32) ([]byte, *big.Int, error) {
	var bigint = new(big.Int)
	bigint.SetBytes(data[0:length])
	return data[length:], bigint, nil
}

func getRsaValues(data []byte) (format string, e *big.Int, n *big.Int, err error) {
	data, length, err := readLength(data)
	if err != nil {
		return
	}

	format = string(data[0:length])
	data = data[length:]

	data, length, err = readLength(data)
	if err != nil {
		return
	}

	data, e, err = readBigInt(data, length)
	if err != nil {
		return
	}

	data, length, err = readLength(data)
	if err != nil {
		return
	}

	data, n, err = readBigInt(data, length)
	if err != nil {
		return
	}

	return
}

func DecodePublicKey(str string) (interface{}, error) {
	// comes in as a three part string
	// split into component parts

	tokens := strings.Split(str, " ")

	if len(tokens) < 2 {
		return nil, fmt.Errorf("Invalid key format; must contain at least two fields (keytype data [comment])")
	}

	key_type := tokens[0]
	data, err := base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		return nil, err
	}

	format, e, n, err := getRsaValues(data)

	if format != key_type {
		return nil, fmt.Errorf("Key type said %s, but encoded format said %s.  These should match!", key_type, format)
	}

	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return pubKey, nil
}



