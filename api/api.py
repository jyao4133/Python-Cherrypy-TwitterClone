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
        print(data)
        return payload
        