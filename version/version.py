#!/usr/bin/env python
# coding:utf-8

import time

__version__"0.1.0"

def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain; charset=UTF-8')])
    if environ['PATH_INFO'] == '/robots.txt':
        yield '\n'.join(['User-agent: *', 'Disallow: /'])
    else:
        timestamp = long(environ['CURRENT_VERSION_ID'].split('.')[1])/2**28
        ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp+8*3600))
        yield "ArkC Server transmit running.\nVersion:%s\n\n%s" % (__version__, ctime)
