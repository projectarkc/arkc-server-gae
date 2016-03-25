#!/usr/bin/env python
# coding:utf-8

from google.appengine.api import memcache
from google.appengine.api import taskqueue
from google.appengine.ext import db

from goagent import process

from utils import AESCipher

INITIAL_INDEX =
SPLIT_CHAR =


def application(environ, start_response):
	if environ['REQUEST_METHOD'] == 'GET' and 'HTTP_X_URLFETCH_PS1' not in environ:
        start_response('200 OK', [('Content-Type', 'text/plain')])
        yield 'ArkC-GAE Python Server works'
        raise StopIteration

    assert environ['REQUEST_METHOD'] == 'POST'
    wsgi_input = environ['wsgi.input']
    input_data = wsgi_input.read(int(environ.get('CONTENT_LENGTH', '0'))
    # TODO: call dataReceived
    dataReceived(input_data)
    start_response('200 OK', [('Content-Type', 'text/plain')]) # TODO: to be finished
    yield ""

def dataReceived(self, sessionid, recv_data):
    """Event handler of receiving some data from client.

    Split, decrypt and hand them back to Control.
    """
    # Avoid repetition caused by ping
    # logging.debug("received %d bytes from client " % len(recv_data) +
    #          addr_to_str(self.transport.getPeer()))

    recvbuffer = memcache.get(sessionid + ".buffer")
    if recvbuffer is None:
    	recvbuffer = ""
    
    
    
    recvbuffer += recv_data

    cipher = getcipher(sessionid)
    if cipher is None:
        pass
        # TODO: error processing

    # a list of encrypted data packages
    # the last item may be incomplete
    recv = recvbuffer.split(SPLIT_CHAR)
    memcache.add(id+".buffer", recv[-1], 1800)
    # leave the last (may be incomplete) item intact
    for text_enc in recv[:-1]:
        text_dec = cipher.decrypt(text_enc)
        # flag is 0 for normal data packet, 1 for ping packet, 2 for auth
        flag = int(text_dec[0])
        if flag == 0:
            reply, conn_id = client_recv(text_dec[1:], sessionid)
            rawpayload  = '0' + conn_id + str(INITIAL_INDEX) + reply
            taskqueue.add(payload = cipher.encrypt(rawpayload) + SPLIT_CHAR, target = "fetchback", url="/fetchback/", 
                headers = {"sessionid":sessionid, "idchar":conn_id})
    

def client_recv(recv, sessionid):
    """Handle request from client.

    Should be decrypted by ClientConnector first.
    """
    conn_id, index, data = recv[:2], int(recv[2:8]), recv[8:]
    #recv_index = memcache.get(conn_id+".index")
    #if recv_index is None:
    #   recv_index = INITIAL_INDEX

    # logging.debug("received %d bytes from client key " % len(data) +
    #          conn_id)
    if data == self.close_char:
    	pass # TODO: do anything?
    elif index == 30:   # confirmation
        pass # TODO: do anything? (Confirmation message)
    elif index == 20:
        # retransmit, do anything?
        pass
    else:
        return process(data), conn_id # correct?

def getcipher(sessionid):
    password = memcache.get(sessionid + ".password")
    iv = memcache.get(sessionid + ".iv")
    if password is None or iv is None:
        q = db.GqlQuery("SELECT * FROM endpoint" +
        "WHERE sessionid = :1", sessionid)
        for rec in q.run(limit=1):
            password = rec.password
            iv = rec.iv
            memcache.add(sessionid+".password", password, 1800)
            memcache.add(sessionid+".iv", iv, 1800)
    try:
        cipher = AESCipher(password, iv)
        return cipher
    except Exception:
        return None

class endpoint(db.Model):
    address = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True, indexed=False)
    iv  = ndb.StringProperty(required=True, indexed=False)
    sessionid = ndb.StringProperty(required=True)
    idchar  = ndb.StringProperty(required=True)