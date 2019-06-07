import cherrypy
import nacl.encoding
import nacl.signing
import base64
import time
import json
import urllib.request
import pprint
import jinja2
from jinja2 import Template
import nacl.utils
import nacl.secret
import nacl.pwhash

import database


class Api(object):
    @cherrypy.expose
    def ping(self):
        return {'response' : "ok"}
    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        #request = cherrypy.request[]
        payload = {'response' : "ok"}
        payload = json.dumps(payload).encode('utf-8')
        data = cherrypy.request.json
        database.addtoDB_broadcast(data)
        return payload

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def rx_privatemessage(self):
        payload = {'response' : "ok"}
        payload = json.dumps(payload).encode('utf-8')
        data = cherrypy.request.json
        database.addtoDB_pms(data)
        return payload


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def ping_check(self):

        payload = {'response' : "ok",
                    'my_time' : str(time.time())}
        payload = json.dumps(payload).encode('utf-8')
        data = cherrypy.request.json

        return payload



       
        