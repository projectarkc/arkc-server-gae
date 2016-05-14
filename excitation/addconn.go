package excitation

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
	//otp "go-otp"
	encoding_ssh "ssh"

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
			ctx.Criticalf("server key missing: %s", err)
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
	//ctx.Infof("%s, %s, %s", record.Clientpub, record.Clientsha1, record.Clientprisha1)
	//write to memcache
	sessionpassword := make([]byte, 16)
	rand.Read(sessionpassword)

	//debug
	//sessionpassword = []byte("aaaaaaaaaaaaaaaa")
	pub_key, err := encoding_ssh.DecodePublicKey(record.Clientpub)
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
	taskqueue.Add(context, t, "excitation")

	//warm up
	t = &taskqueue.Task{
		Path:   "/fetchfrom/",
		Method: "GET",
	}
	taskqueue.Add(context, t, "fetchfrom1")
	t = &taskqueue.Task{
		Path:   "/fetchback/",
		Method: "GET",
	}
	taskqueue.Add(context, t, "fetchback1")

	w.Header().Add("X-Session-Id", Sessionid)
	w.WriteHeader(resp.StatusCode)
	n, err := io.Copy(w, reply)
	if err != nil {
		context.Errorf("io.Copy after %d bytes: %s", n, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
