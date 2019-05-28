import cherrypy
import nacl.encoding
import nacl.signing
import base64
import json
import urllib.request
import pprint
import nacl.utils
startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "Welcome! This is a test website for COMPSYS302!<br/>"
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Here is some bonus text because you've logged in! <a href='/signout'>Sign out</a>"
        except KeyError: #There is no username
            
            Page += "Click here to <a href='login'>login</a>."
        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        cherrypy.session['username'] = username
        cherrypy.session['password'] = password
        check_key(username, password)
        error = authoriseUserLogin(username, password)

        if error == 0:


            response = ping(username, password)
            if(response["response"] == "ok"):
                report(username, password)
            else:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###
def pubAuth():
    username = cherrypy.session['username'] #"jyao413"   
    password = cherrypy.session['password']#"tigerj2_590856141" #
    url = "http://cs302.kiwi.land/api/add_pubkey"



# Generate a new random signing key
    hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
    print(hex_key)


# Sign a message with the signing key

# Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key

# Serialize the verify key to send it to a third party
    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

#create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey" : pubkey_hex_str,
	"username" : username,
	"signature" : signature_hex_str
    }
    payload = json.dumps(payload).encode('utf-8')

#STUDENT TO COMPLETE:
#1. convert the payload into json representation, 
#2. ensure the payload is in bytes, not a string

#3. pass the payload bytes into this function
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    if (JSON_object["response"] == "ok"):
        print("Successfully added a pubkey for user")
        cherrypy.session['signing_key'] = signing_key
        cherrypy.session['pubkey'] = pubkey_hex_str
        return 0
    else:
        print ("Fail")
        return 1

        

def authoriseUserLogin(username, password):
    print("Log on attempt from {0}:{1}".format(username, password))
    success = ping(username,password)
    if (success["response"] == "ok"):
        print("Success")
        return 0
    else:
        print("Failure")
        return 1


def ping(username, password):

    url = "http://cs302.kiwi.land/api/ping"   
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    payload = {
        
        "username" : username,
        "pubkey" : cherrypy.session['pubkey'],
        "Signature" : cherrypy.session['signed_key']

        
    }
    payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    if (JSON_object["response"] == "ok"):
        print("Ping success")
        return JSON_object
    else:
        print ("Fail")
        return JSON_object


def get_privatedata(username, password):

    url = "http://cs302.kiwi.land/api/get_privatedata"

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    try:
        req = urllib.request.Request(url,  headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    return JSON_object

def report(username, password):
    url = "http://cs302.kiwi.land/api/report"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "incoming_pubkey" : cherrypy.session['pubkey'],
        "connection_address" : "127.0.0.1:8000",
        "connection_location" : "2"
        
    }
    payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    return JSON_object

def check_key(username, password):

    private_data = get_privatedata(username, password)
    private_data_dict = json.loads(private_data['privatedata'])
    if (private_data_dict['prikeys'] == ""):
        pubAuth()
    else:
        cherrypy.session['privatekey'] = private_data_dict['prikeys']
        print(cherrypy.session['privatekey'])
                #decode private signing key
        hex_key = bytes(cherrypy.session['privatekey'] , 'utf-8')
        hex_key_str = cherrypy.session['privatekey']
        signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
        verify_key = signing_key.verify_key
        verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_strs = pubkey_hex.decode('utf-8')
        cherrypy.session['pubkey'] = pubkey_hex_strs
        cherrypy.session['signed_key'] = hex_key_str
            