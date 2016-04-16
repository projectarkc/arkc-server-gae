#!/usr/bin/env python
# coding:utf-8

from google.appengine.api import memcache
from google.appengine.api import taskqueue
from google.appengine.ext import ndb

import logging
import hashlib

from goagent import process, NotFoundKey, GAEfail, PermanentFail, TimeoutFail, Nonsense

from utils import AESCipher

INITIAL_INDEX = 100000
SPLIT_CHAR = chr(27) + chr(28) + chr(31)
CLOSE_CHAR = chr(4) * 5


class Endpoint(ndb.Model):
    Address = ndb.StringProperty(required=True)
    Password = ndb.BlobProperty(required=True, indexed=False)
    IV = ndb.StringProperty(required=True, indexed=False)
    Sessionid = ndb.StringProperty(required=True)
    IDChar = ndb.StringProperty(required=True)

def application(environ, start_response):
    if environ['REQUEST_METHOD'] == 'GET' and 'HTTP_X_URLFETCH_PS1' not in environ:
        start_response('200 OK', [('Content-Type', 'text/plain')])
        yield 'ArkC-GAE Python Server works'
        raise StopIteration
    #print(environ)
    try:
        assert environ['REQUEST_METHOD'] == 'POST'
        sessionid = environ['HTTP_SESSIONID']
        length = int(environ.get('CONTENT_LENGTH', '0'))
        assert length > 0
    except Exception:
        #start_response('400 Bad request', [('Content-Type', 'text/plain')])
        start_response('200 Bad request', [('Content-Type', 'text/plain')])
        yield "HTTP 400\nBAD REQUEST\ncannot parse\n"
        raise StopIteration

    wsgi_input = environ['wsgi.input']
    input_data = wsgi_input.read(length)
    #print(input_data)
    #print(sessionid)

    try:
        dataReceived(sessionid, input_data)
    #except GAEfail:
        #start_response('400 Bad request', [('Content-Type', 'text/plain')])
    #    start_response('200 Bad request', [('Content-Type', 'text/plain')])
    #    yield "HTTP 400\nBAD REQUEST\ndon't work with GoAgent\n"
    #    raise StopIteration
    except NotFoundKey:
        #start_response('400 Bad request', [('Content-Type', 'text/plain')])
        start_response('200 Bad request', [('Content-Type', 'text/plain')])
        yield "HTTP 400\nBAD REQUEST\nkey not found\n"
        raise StopIteration
    except Nonsense:
        start_response('202 Accepted', [('Content-Type', 'text/plain')])
        yield "HTTP 202\nAccepted\nMessage processed."
        raise StopIteration
    except GAEfail:
        start_response('211 GAE FAIL', [('Content-Type', 'text/plain')])
        yield "HTTP 211\nGAE FAIL\n"
        raise StopIteration
    except PermanentFail:
        start_response('212 FETCH FAIL', [('Content-Type', 'text/plain')])
        yield "HTTP 212\nFETCH FAIL\n"
        raise StopIteration
    except TimeoutFail:
        start_response('211 GAE FAIL', [('Content-Type', 'text/plain')])
        yield "HTTP 211\nGAE FAIL\n"
        raise StopIteration

    # TODO: to be finished
    start_response('200 OK', [('Content-Type', 'text/plain')])
    yield "Processed"


def dataReceived(Sessionid, recv_data):
    """Event handler of receiving some data from client.

    Split, decrypt and hand them back to Control.
    """
    # Avoid repetition caused by ping
    # logging.debug("received %d bytes from client " % len(recv_data) +
    #          addr_to_str(self.transport.getPeer()))

    cipher = getcipher(Sessionid)
    if cipher is None:
        raise NotFoundKey
    # leave the last (may be incomplete) item intact
    try:
        text_dec = cipher.decrypt(recv_data)
    except Exception as err:
        print(recv_data)
        print(len(recv_data))
        raise err
    if len(text_dec) == 14:
        raise Nonsense

    # flag is 0 for normal data packet, 1 for ping packet, 2 for auth
    flag = int(text_dec[0])
    if flag == 0:
        reply, conn_id = client_recv(text_dec[1:])
        prefix = '0' + conn_id + str(INITIAL_INDEX)
        rawpayload = ""
        for line in reply:
            rawpayload += line
            #print(line)
        tosend = ""
        if len(rawpayload) + len(prefix) > 4096:
            while len(rawpayload) + len(prefix) > 4096:
                tosend += prefix + rawpayload[:4096-len(prefix)]
                rawpayload = rawpayload[:4096-len(prefix)]
            tosend += prefix + rawpayload
        h = hashlib.sha1()
        h.update(tosend)
        #print(tosend)
        payloadHash = h.hexdigest()[16]
        memcache.add(Sessionid + '.' + payloadHash, cipher.encrypt(tosend) + SPLIT_CHAR, 900)
        taskqueue.add(queue_name="fetchback1", url="/fetchback/",
                      headers={"Sessionid": Sessionid, "IDChar": conn_id,
                      "PAYLOADHASH":payloadHash})


def client_recv(recv):
    """Handle request from client.

    Should be decrypted by ClientConnector first.
    """
    conn_id, index, data = recv[:2], int(recv[2:8]), recv[8:]
    # recv_index = memcache.get(conn_id+".index")
    # if recv_index is None:
    #   recv_index = INITIAL_INDEX

    # logging.debug("received %d bytes from client key " % len(data) +
    #          conn_id)
    if data == CLOSE_CHAR:
        pass  # TODO: do anything?
    elif index == 30:   # confirmation
        pass  # TODO: do anything? (Confirmation message)
    elif index == 20:
        # retransmit, do anything?
        pass
    else:
        return process(data), conn_id  # correct?


def getcipher(Sessionid):
    Password = memcache.get(Sessionid + ".Password")
    IV = memcache.get(Sessionid + ".IV")
    if Password is None or IV is None:
        q = Endpoint.query(Endpoint.Sessionid == Sessionid)
        for rec in q.fetch(1):
            #logging.warning("Found")
            Password = str(rec.Password)
            IV = rec.IV
            memcache.add(Sessionid + ".Password", Password, 1800)
            memcache.add(Sessionid + ".IV", IV, 1800)
    #print("PASSWORD IS" + repr(Password))
    #print("IV IS" + repr(IV))
    try:
        
        cipher = AESCipher(Password, IV)
        return cipher
    except Exception:
        logging.warning("Not Found")
        return None



