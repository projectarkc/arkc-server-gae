// A web app for Google App Engine that proxies HTTP requests and responses to a
// Tor relay running meek-server.
package addconn

import (
	"io"
	"net/http"
	"net"
	"net/url"
	"time"
	"bufio"
	"fmt"
	"bytes"
	"strconv"

	"crypto/cipher"
	"crypto/rsa"
	"crypto/rand"
    "crypto/x509"
    "crypto/aes"
    "encoding/pem"

	"appengine"
	"appengine/urlfetch"
	"appengine/datastore"
	"appengine/memcache"
)

const (
	// A timeout of 0 means to use the App Engine default (5 seconds).
	urlFetchTimeout = 20 * time.Second
)

var serverpri *rsa.PrivateKey
var ready = false

type endpoint struct {
	address    string
	password   string
	iv         string // iv is also mainpassword
	sessionid  string
	idchar     string
}

type client struct {
	clientsha1 		string
	clientpub    	string
	clientprisha1   string
}

type server struct {
	public	string
	private	string
}

// Join two URL paths.
// func pathJoin(a, b string) string {
// 	if len(a) > 0 && a[len(a)-1] == '/' {
// 		a = a[:len(a)-1]
// 	}
// 	if len(b) == 0 || b[0] != '/' {
// 		b = "/" + b
// 	}
// 	return a + b
// }

// We reflect only a whitelisted set of header fields. In requests, the full
// list includes things like User-Agent and X-Appengine-Country that the Tor
// bridge doesn't need to know. In responses, there may be things like
// Transfer-Encoding that interfere with App Engine's own hop-by-hop headers.
var reflectedHeaderFields = []string{
	"Content-Type",
	"X-Session-Id",
}

// Get the original client IP address as a string. When using the standard
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
func processRequest(forward string, payload io.Reader, sessionid string) (*http.Request, error){
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
	c.Header.Add("X-Session-Id", sessionid)
	return c, nil
}

func loadserverkey(ctx appengine.Context) error {
	//load key from datastore or memcache
	var block *pem.Block
	if item, err := memcache.Get(ctx, "serverpri"); err != memcache.ErrCacheMiss {
        block, _ = pem.Decode(item.Value)
	} else {
		var record []server
		q := datastore.NewQuery("server").Limit(1)
		_, err = q.GetAll(ctx, &record)
		if err != nil || len(record) == 0 {
			ctx.Errorf("server key missing: %s", err)
			return fmt.Errorf("Error when searching for server keys")
		}
		block, _ = pem.Decode([]byte(record[0].private))
		item = &memcache.Item{
			Key:	"server",
			Value: 	[]byte(record[0].private),
		}
		_ = memcache.Add(ctx, item)
	}
    serverpri, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
    return nil
}

func getpreviousindex(mainpw []byte, number int, ctx appengine.Context) ([]byte, string, error) {
	var record []endpoint
	var last int
	// use memcache as buffer
	q := datastore.NewQuery("endpoint").Filter("iv ==", string(mainpw[:])).Order("iv").Order("idchar")
	_, err = q.GetAll(ctx, &record)
	if err != nil {
		return "", "", err
	}
	if len(record) >= number {
		return "", "", fmt.Errorf("Already enough connections")
	} else {
		// method in doubt
		last := strconv.Atoi(record[0].idchar)
		for _, rec := range record {
			if strconv.Atoi(rec.idchar)-last >= 2{
				break
			}
		}
		return "", strconv.Itoa(last + 1), nil
	}


}

func getauthstring(body *bufio.Reader, ctx appengine.Context) (string, io.Reader, string, string, string, string, error) {
	//return
	// URL to send, string
	// contents, io.Reader
	// clientid, string
	// password, string
	// iv, string
	// idchar, string
	// error
	var record []client

	sha1, _, err := body.ReadLine()
	if err == nil {
		return "", nil, "", "", "", "", err
	}
	url, _, err := body.ReadLine()
	if err == nil {
		return "", nil, "", "", "", "", err
	}
	mainpw, _, err := body.ReadLine()
	if err == nil {
		return "", nil, "", "", "", "", err
	}
	number, _, err := body.ReadLine()
	if err == nil {
		return "", nil, "", "", "", "", err
	}
	i, err := strconv.Atoi(number)
	if err != nil {
		return "", nil, "", "", "", "", err
	}
	previousrecord, idchar, err := getpreviousindex(mainpw, i, ctx)
	if err == nil {
		return "", nil, "", "", "", "", err
	}
	//try to load from memcache
	q := datastore.NewQuery("client").Limit(1).
        Filter("clientsha1 =", string(sha1[:]))
	_, err = q.GetAll(ctx, &record)
	if err != nil {
		return "", nil, "", "", "", "", err
	}
	if len(record) == 0 {
		return "", nil, "", "", "", "", fmt.Errorf("not found")
	}
	//write to memcache
	sessionpassword := make([]byte, 16)
	rand.Read(sessionpassword)
	pubkey, err := x509.ParsePKIXPublicKey([]byte(record[0].clientpub))
	if !ready {
		err = loadserverkey(ctx)
		if err != nil {
			return "", nil, "", "", "", "", err
		}
		ready = true
	}

	part1, _ := rsa.SignPKCS1v15(nil, serverpri, 0, []byte(mainpw))
	part2, _ := rsa.EncryptPKCS1v15(nil, pubkey.(*rsa.PublicKey), sessionpassword)
	contents := bytes.NewBuffer(part1)
	contents.Write(part2)
	contents.WriteString(idchar)
	contents.Write(previousrecord)
	// TODO: length may change? manual split string?
	return string(url[:]), contents, string(sha1[:]), string(sessionpassword[:]), string(mainpw[:]), string(idchar[:]), nil
}

func authverify(body *bufio.Reader, idchar string, authstring string, iv string) error {
	//verify if the password is correct
	value, _, err :=body.ReadLine()
	if err == nil {
		return err
	}
	aescipher, err := aes.NewCipher([]byte(authstring))
	if err == nil {
		return err
	}
	// TODO: Blocksize???
	stream := cipher.NewCFBDecrypter(aescipher, []byte(iv))
	stream.XORKeyStream(value, value)
	if bytes.Compare(value, []byte("AUTHENTICATED" + idchar)) != 0 {
		return fmt.Errorf("AUTH FAIL")
	} else {
		//TODO throw the rest to task queue?
		return nil
	}

}

func storestring(ctx appengine.Context, url string, sessionid string, authstring string, iv string, idchar string) (io.Reader, error) {
	//use Datastore and Memcache to store the string
	//return
	// current status, io.Reader
	// error
	var items []*memcache.Item
	record := endpoint{
		address:	url,
		password:   authstring,
		iv:			iv,
		sessionid:  sessionid,
		idchar:     idchar,
	}
	key := datastore.NewIncompleteKey(ctx, "endpoint", nil)
	_, err := datastore.Put(ctx, key, &record)
	if err != nil {
        return nil, err
    }
    items = append(items,
    	&memcache.Item{
    		Key:	sessionid + ".address",
    		Value:	[]byte(url),
    	},
    	&memcache.Item{
    		Key:	sessionid + ".password",
    		Value:	[]byte(authstring),
    	},
    	&memcache.Item{
    		Key:	sessionid + ".iv",
    		Value:	[]byte(iv),
    	},
    	&memcache.Item{
    		Key:	sessionid + ".idchar",
    		Value:	[]byte(idchar),
    	},
    )
    _ = memcache.AddMulti(ctx, items)
    // TODO get status
    return bytes.NewBuffer([]byte("")), nil

}

func handler(w http.ResponseWriter, r *http.Request) {
	context := appengine.NewContext(r)
	forward, payload, clientid, passwd, iv, idchar, err := getauthstring(bufio.NewReader(r.Body), context)
	if err != nil {
		context.Errorf("parseRequest: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessionid := r.Header.Get("X-Session-Id")
	fr, err := processRequest(forward, payload, sessionid)
	if err != nil {
		context.Errorf("processRequest: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	err = authverify(bufio.NewReader(resp.Body), idchar, passwd, iv)
	if err != nil {
		context.Errorf("Authentication: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	reply ,err := storestring(context, forward, clientid, passwd, iv, idchar)
	if err != nil {
		context.Errorf("Saving: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("X-Session-Id", sessionid)
	w.WriteHeader(resp.StatusCode)
	n, err := io.Copy(w, reply)
	if err != nil {
		context.Errorf("io.Copy after %d bytes: %s", n, err)
	}
	// TODO
	//fetch from the server immediately
}

func init() {
	http.HandleFunc("/", handler)
}
