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
import threading
import database
env = Environment(loader=FileSystemLoader('static'), autoescape=True)
startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"
pageHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/flex.css' /></head><body>"
pmHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/privatemessage.css' /></head><body>"

database.createDB_userlist()
database.createDB_pmdata()
database.createDB_senderdata()
database.createDB_messagedata()
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
        Page = startHTML + '''<!DOCTYPE html>
                            <html>
                            <head>
                            <link rel='stylesheet' href='/static/example.css' />
                            </head>
                            <body>
                            <header>
                            <div class="header-block">
                            <div id="demoFont">Twitmore</div>
                            </div>
                            </header>
                            </body>
                            </html>'''
        cherrypy.response.status = 404
        return Page
    
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def showmessages(self):
            user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])
            report(cherrypy.session['username'],cherrypy.session['password'])
            test = decrypt_privdata()
            send_dict = json.dumps(user_list)
            broadcasts = database.get_broadcast_messages()
            template = env.get_template('broadcastmessage.html')
            htmldict = render_template(template, user_list, broadcasts)
            dict_html = {"data" : htmldict}
            dict_dump = json.dumps(dict_html)
            return dict_dump

    @cherrypy.tools.json_out()
    @cherrypy.expose
    def showusers(self):
        user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])

        template = env.get_template('userlist.html')
        htmldict = render_template_user(template, user_list)
        dict_html = {"data" : htmldict}
        dict_dump = json.dumps(dict_html)

        return dict_dump

    @cherrypy.tools.json_out()
    @cherrypy.expose
    def poll(self):
        user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])

        for user in user_list:
            ip = user['connection_address'] 
            thread = threading.Thread(target=ping_check, args=(cherrypy.session['username'],cherrypy.session['password'],ip,cherrypy.session['external_ip']))
            thread.start()       
        dict_html = {"data" : ""}
        dict_dump = json.dumps(dict_html)
        print(ip)
        return dict_dump

    @cherrypy.tools.json_out()
    @cherrypy.expose
    def showpms(self):
        user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])
        template = env.get_template('pm.html')
        report(cherrypy.session['username'],cherrypy.session['password'])

        pms = database.get_pms(cherrypy.session['username'],cherrypy.session['signing_key'])
        empty_list = []
        for person in pms:
            if (person['sender'] == cherrypy.session['private_username']):
                empty_list.append(person)
        htmldict = render_template(template, user_list,empty_list)
        dict_html = {"data" : htmldict}
        dict_dump = json.dumps(dict_html)
        return dict_dump


    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):    
        Page = startHTML
        cherrypy.session['external_ip'] = get_ownip()+":"+"8000"

        try:
            user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])
            report(cherrypy.session['username'],cherrypy.session['password'])
            test = decrypt_privdata()
            send_dict = json.dumps(user_list)
            broadcasts = database.get_broadcast_messages()
            template = env.get_template('login.html')
            filter_list = []
            if(cherrypy.session['filter'] == "on"):
                for broadcast in broadcasts:
                    if (cherrypy.session['temp_person'] == broadcast['loginserver_record']):
                        filter_list.append(broadcast)
            htmldict = render_templates(template, user_list, broadcasts,filter_list)
            Page = pageHTML
   
       
            Page += htmldict

            return Page
                         



        except KeyError: #There is no username
            Page +='''<div class="login-page">
                    <div class="form">
                        <button onclick="window.location.href = '/login';">login</button>
                        </form>
                        </div>
                    </div>'''
            
            return Page
        
    @cherrypy.expose
    def broadcast_box(self):

        try:
            template = env.get_template('broadcastbox.html')
            htmld = single_render(template)
            Page = htmld


        except KeyError:
            Page = startHTML + "You have not logged in, please login!<br/>"

        return Page
    @cherrypy.expose
    def get_broadcast(self, broadcast = None):
        try:
            Page = startHTML + "Successfully broadcast a message<br/>"
            cherrypy.session['broadcast'] = broadcast
            poll = list_users(cherrypy.session['username'],cherrypy.session['password'])

            ts = time.time()
            record = cherrypy.session['loginserver_record']
            message_bytes = bytes(record + cherrypy.session['broadcast'] + str(ts), encoding='utf-8')
            signed = cherrypy.session['signing_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
            signature_hex_str = signed.signature.decode('utf-8')

            for user in poll:
                ip = user['connection_address'] 
                thread = threading.Thread(target=send_broadcast, args=(cherrypy.session['username'],cherrypy.session['password'],cherrypy.session['broadcast'],ip,record,signature_hex_str))
                thread.start()                   
                    #send_broadcast(cherrypy.session['username'],cherrypy.session['password'],cherrypy.session['broadcast'])
            Page += "Click here to return to the title <a href='/'>page</a>."

        except KeyError:
            Page = startHTML + "Oops something went wrong<br/>"
        return Page

    @cherrypy.expose
    def receiver_box(self):
        try:
            
            template = env.get_template('receivebox.html')
            htmld = single_render(template)
            Page = htmld


        except KeyError:
            Page = startHTML + "You have not logged in, please login!<br/>"

        return Page  

    @cherrypy.expose
    def privatemessage_box(self, Username = None):
        try:
            Page = pmHTML
            cherrypy.session['private_username'] = Username
            online_bool = False
            poll = list_users(cherrypy.session['username'],cherrypy.session['password'])
            for person in poll:
                if (person['username'] == cherrypy.session['private_username']):
                    online_bool = True

            template = env.get_template('privatemessage.html')
            pms = database.get_pms(cherrypy.session['username'],cherrypy.session['signing_key'])
            sent_pms = database.get_sentpms(cherrypy.session['private_username'])

            empty_list = []
            empty_pm = []

            #filter for received pms (don't want to show everything)
            for person in pms:
                if (person['sender'] == cherrypy.session['private_username']):
                    empty_list.append(person)

            #filter for sent pms to specific person (don't want to show everything)
            for person in sent_pms:
                if (person['sender'] == cherrypy.session['username']):
                    empty_pm.append(person)
            htmldict = render_template_pm(template, poll, empty_list, empty_pm)
            Page = pmHTML
            Page += htmldict

            if (online_bool == False):
                Page = startHTML + "The person you have entered is not online or does not exist!<br/>"
                Page += "Click here to return to  <a href='/receiver_box'>try again</a>."
                

        except KeyError:
            Page = startHTML + "Oops something went wrong<br/>"
        return Page

    @cherrypy.expose
    def send_privatemessage(self, Message = None):
        try:
            cherrypy.session['message'] = Message
            send_privatemessage(cherrypy.session['username'],cherrypy.session['password'],cherrypy.session['message'])
            payload = {
                'message' : cherrypy.session['message'],
                'sender_created_at' : str(time.time()),
                'target_username' : cherrypy.session['private_username'],
                'current_username' : cherrypy.session['username']
            }
            database.addtoDB_sentpms(payload)
            raise cherrypy.HTTPRedirect('/privatemessage_box?Username=' + cherrypy.session['private_username'])
        except KeyError:
            Page = startHTML + "Oops something went wrong<br/>"
        return Page


    @cherrypy.expose
    def login(self, bad_attempt = 0, *vars, **kwargs):
        cherrypy.session['filter'] = "off"
        Page = startHTML 
        cherrypy.session['block_broadcasts'] = []
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"


        template = env.get_template('firstpage.html')
        
        htmld = single_render(template)
        Page += htmld


        
        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, password2 = None, overwrite = None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""

        cherrypy.session['username'] = username
        cherrypy.session['password'] = password
        cherrypy.session['password2'] = password2
        if (overwrite == "on"):
            pubAuth()
            add_privdata(username, password, password2)
        check_key(username, password)

        error = authoriseUserLogin(username, password)  
        if error == 0:
            

            check_key(username, password)
            response = ping(username, password)
            if(response["response"] == "ok" and cherrypy.session['failflag'] == "pass"):
                cherrypy.session['status'] = "online"
                report(username, password)
                
                get_record(username,password)
            else:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        cherrypy.session['status'] = "offline"
        report(cherrypy.session['username'],cherrypy.session['password'])
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def away(self):
        cherrypy.session['status'] = "away"
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def online(self):
        cherrypy.session['status'] = "online"
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def block_user(self, Message = None):
        print(Message)
        person = Message
        cherrypy.session['temp_person'] = person
        print(cherrypy.session['temp_person'])
        cherrypy.session['filter'] = "on"
        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###
def pubAuth():
    username = cherrypy.session['username']   
    password = cherrypy.session['password'] #
    url = "http://cs302.kiwi.land/api/add_pubkey"



# Generate a new random signing key
    hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
    cherrypy.session['temp_key'] = signing_key
    hex_key_str = hex_key.decode("utf-8")
    cherrypy.session['new_privkey'] = hex_key_str
    


# Sign a message with the signing key

# Obtain the verify key for a given signing key                  
    verify_key = signing_key.verify_key

# Serialize the verify key to send it to a third party
    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    cherrypy.session['signed_key'] = pubkey_hex_str
    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    cherrypy.session['signature_hex_str'] = signature_hex_str
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

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    cherrypy.session['loginserver_record'] = JSON_object['loginserver_record']
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
    try:
        success = ping(username,password)
        if (success["response"] == "ok"):
            print("Success")
            return 0
        else:
            print("Failure")
            return 1
    except KeyError:
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
            
        JSON_object = json.loads(data.decode(encoding))
        return JSON_object
    except urllib.error.HTTPError as error:
        raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                



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
        "connection_address" : cherrypy.session['external_ip'],
        "connection_location" : 2,
        "status" : cherrypy.session['status']
        
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

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    return JSON_object

def check_key(username, password):
    try:
        private_data = get_privatedata(username, password)
        private_data_dict = private_data['privatedata']
        cherrypy.session['encrypted_priv']=private_data_dict
        private_data_dict = decrypt_privdata()
        private_data_dict = json.loads(private_data_dict)
        if (private_data_dict['prikeys'][0] == ""):
            pubAuth()
            cherrypy.session['privatekey'] = private_data_dict['prikeys'][0]
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
            cherrypy.session['signing_key'] = signing_key

        else:
            cherrypy.session['privatekey'] = private_data_dict['prikeys'][0]
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
            cherrypy.session['signing_key'] = signing_key
    except KeyError:
        raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                
     


def send_broadcast(username,password,message,ip,record,signature_hex_str):
    url = "http://"+ip+"/api/rx_broadcast"
    # Generate a new random signing key 
    print(ip)
    ts = time.time()
    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "message" : message,
        "sender_created_at" : str(ts),
        "loginserver_record" : record,   
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
        
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        response.close()
    except (urllib.error.HTTPError,urllib.error.URLError,json.decoder.JSONDecodeError) as error:
        return
    


def get_record(username, password):
    url = "http://cs302.kiwi.land/api/get_loginserver_record"
 
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())

    JSON_object = json.loads(data.decode(encoding))
    cherrypy.session['loginserver_record'] = JSON_object['loginserver_record']
    
def list_users(username, password):
    url = "http://cs302.kiwi.land/api/list_users"
 
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())

    JSON_object = json.loads(data.decode(encoding))

    return JSON_object['users']

def send_privatemessage(username, password, message):
        url = "http://e7871110.ngrok.io/api/rx_privatemessage"

        userlist = list_users(username, password)
        for person in userlist:

            if (person['username'] == cherrypy.session['private_username']):
                target_pubkey = person['incoming_pubkey']
                target_pubkey_bytes = bytes(target_pubkey, 'utf-8')


        message = bytes(cherrypy.session['message'], 'utf-8')
        verifykey = nacl.signing.VerifyKey(target_pubkey_bytes, encoder=nacl.encoding.HexEncoder)
        publickey = verifykey.to_curve25519_public_key()
        sealed_box = nacl.public.SealedBox(publickey)
        encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
        message_en = encrypted.decode('utf-8')
        ts = str(time.time())

        message_bytes = bytes(cherrypy.session['loginserver_record'] + target_pubkey + cherrypy.session['private_username'] + message_en + str(ts), encoding='utf-8')

        signed = cherrypy.session['signing_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "sender_created_at" : ts,
            "loginserver_record" : cherrypy.session['loginserver_record'],
            "target_pubkey" : target_pubkey, 
            "target_username" : cherrypy.session['private_username'],
            "signature" : signature_hex_str,
            "encrypted_message" : message_en

        }
        payload = json.dumps(payload).encode('utf-8')
        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()
            
            JSON_object = json.loads(data.decode(encoding))
            print(JSON_object)
        except urllib.error.HTTPError as error:
            print(error.read())


def add_privdata(username, password, password2):
    
    ts = str(time.time())
    prikeys = [cherrypy.session['new_privkey']]
    blocked_pubkeys = []
    blocked_usernames = []
    blocked_message_signatures = []
    blocked_words = []
    favourite_message_signatures = []
    friends_usernames = []    
    
    private_datas = {
        "prikeys" : prikeys,
        "blocked_pubkeys" : blocked_pubkeys,
        "blocked_usernames" : blocked_usernames,
        "blocked_message_signatures" : blocked_message_signatures,
        "blocked_words" : blocked_words,
        "favourite_message_signatures" : favourite_message_signatures,
        "friends_usernames" : friends_usernames
    }
    
    private_data = json.dumps(private_datas)
    password2 = bytes(password2, 'utf-8')
    #create a secret box 
    kdf = nacl.pwhash.argon2i.kdf # our key derivation function
    ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
    mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
    salt_bytes = password2 * 16 
    salt = salt_bytes[0:16]
    key = kdf(nacl.secret.SecretBox.KEY_SIZE, password2, salt,ops,mem)
    box = nacl.secret.SecretBox(key)
    #create a unique nonce and encrypt our private data

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE) 
    encrypted = box.encrypt(bytes(private_data,'utf-8'),nonce)
    data = base64.b64encode(encrypted).decode("utf-8")

    url = "http://cs302.kiwi.land/api/add_privatedata"
    message_bytes = bytes(data + cherrypy.session['loginserver_record'] + ts, encoding='utf-8')

    signed = cherrypy.session['temp_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "privatedata" : data,
        "client_saved_at" : ts,
        "loginserver_record" : cherrypy.session['loginserver_record'],
        "signature" : signature_hex_str
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

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)


def decrypt_privdata():
    try:
        password_bytes = bytes(cherrypy.session['password2'], 'utf-8')
        kdf = nacl.pwhash.argon2i.kdf # our key derivation function
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        salt_bytes = password_bytes * 16 
        salt = salt_bytes[0:16]
        key = kdf(nacl.secret.SecretBox.KEY_SIZE, password_bytes, salt,ops,mem)
        box = nacl.secret.SecretBox(key)

        decode_data = base64.b64decode(cherrypy.session['encrypted_priv'])

        plaintext = box.decrypt(decode_data)
        cherrypy.session['failflag'] = "pass"

        return plaintext
    except nacl.exceptions.CryptoError:
        raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        cherrypy.session['failflag'] = "fail"
        cherrypy.lib.sessions.expire()
        
def ping_check(username, password,ip,curr_ip):
    url = "http://" + ip + "/api/ping_check"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    payload = {
        'my_time' : str(time.time()),
        'connection_address' : curr_ip,
        'connection_location' : 2
    }
    payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        response.close()
    except (urllib.error.HTTPError,urllib.error.URLError,json.decoder.JSONDecodeError) as error:
        return


def render_template(template, list_user, message_list):
    return template.render(user_list=list_user, message_list = message_list)

def render_templates(template, list_user, message_list, filter_list):
    return template.render(user_list=list_user, message_list = message_list, filter_list=filter_list)

def render_template_pm(template, list_user, message_list, sent_list):
    return template.render(user_list=list_user, message_list = message_list, sent_list = sent_list)

def render_template_user(template, list_user):
    return template.render(user_list=list_user)

def single_render(template):
    return template.render()

def get_ownip():
    try:
        url = "https://api.ipify.org/?format=json"
        ip_req = urllib.request.Request(url=url)
        response = urllib.request.urlopen(ip_req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        ip_list = json.loads(data.decode(encoding))
        if 'ip' in ip_list:
            ip = ip_list['ip']
        return ip
    except urllib.error.URLError as e:
        print(e)


