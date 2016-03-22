#!/usr/bin/env python
# coding:utf-8

from google.appengine.api import memcache

from goagent import process

INITIAL_INDEX =
SPLIT_CHAR =


def application(environ, start_response):
	if environ['REQUEST_METHOD'] == 'GET' and 'HTTP_X_URLFETCH_PS1' not in environ:
        start_response('200 OK', [('Content-Type', 'text/plain')])
        yield 'ArkC-GAE Python Server works'
        raise StopIteration

    assert environ['REQUEST_METHOD'] == 'POST'

    # TODO: call dataReceived

    start_response('200 OK', [('Content-Type', 'text/plain')]) # TODO: to be finished

def dataReceived(self, sessionid, recv_data):
    """Event handler of receiving some data from client.

    Split, decrypt and hand them back to Control.
    """
    # Avoid repetition caused by ping
    # logging.debug("received %d bytes from client " % len(recv_data) +
    #          addr_to_str(self.transport.getPeer()))

    recvbuffer = memcache.get(sessionid + "buffer")
    if recvbuffer is None:
    	recvbuffer = ""
    index = memcache.get(sessionid+"index")
    if index is None:
    	index = INITIAL_INDEX
    recvbuffer += recv_data

    # TODO: Get cipher

    # a list of encrypted data packages
    # the last item may be incomplete
    recv = recvbuffer.split(SPLIT_CHAR)
    # leave the last (may be incomplete) item intact
    for text_enc in recv[:-1]:
        text_dec = cipher.decrypt(text_enc)
        # flag is 0 for normal data packet, 1 for ping packet, 2 for auth
        flag = int(text_dec[0])
        if flag == 0:
        client_recv(text_dec[1:], sessionid)

        
    memcache.add(id+"buffer", recv[-1], 1800)

def client_recv(recv, sessionid):
    """Handle request from client.

    Should be decrypted by ClientConnector first.
    """
    conn_id, index, data = recv[:2], int(recv[2:8]), recv[8:]
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
        yield process(data) # correct?
