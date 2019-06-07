import nacl.utils
from nacl.public import PrivateKey, SealedBox

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
from jinja2 import Environment
from jinja2 import FileSystemLoader
import nacl.utils
import nacl.secret
import nacl.pwhash

import database


skbob = "e8fc12930362c9849989a332e50bb696a588667d89630a8c2025860cc998e447"
message_en = "255ab279aa033f69e44d084b403301436aec37c3885858a0c5607bec61d9d52a79805c6a0ccf748cca828f6974019572e0b4ca541e"
message_en4 = message_en.encode('utf-8')
unseal_box = SealedBox(skbob)