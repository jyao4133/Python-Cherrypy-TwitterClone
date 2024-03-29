#--------------------------------------------------------------------------------------------------
#Main python file. Functions and server commands are all used here to do various commands
#--------------------------------------------------------------------------------------------------

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
import main
import database


env = Environment(loader=FileSystemLoader('static'), autoescape=True)
startHTML = "<html><head><title>Twitmore</title><link rel='stylesheet' href='/static/example.css' /></head><body>"
pageHTML = "<html><head><title>Twitmore</title><link rel='stylesheet' href='/static/flex.css' /></head><body>"
pmHTML = "<html><head><title>Twitmore</title><link rel='stylesheet' href='/static/privatemessage.css' /></head><body>"

#if database doesn't already exist, create them. Otherwise these functions are "do nothing" functions
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
        Page = startHTML 
        template = env.get_template('default.html')
        htmld = single_render(template)
        Page += htmld

        cherrypy.response.status = 404
        return Page
    #Funtion to interface with JS to dynamically refresh page
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def showmessages(self):
            user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])
            report(cherrypy.session['username'],cherrypy.session['password'])
            test = decrypt_privdata()
            send_dict = json.dumps(user_list)
            broadcasts = database.get_broadcast_messages()
            blocked_users = cherrypy.session['temp_privdata']['blocked_usernames']
            temp_broadcasts = []
            for person in blocked_users:
                for broadcast in broadcasts:
                    if(broadcast['loginserver_record'] == person):
                        temp_broadcasts.append(broadcast)
            broadcasts = [x for x in broadcasts if x not in temp_broadcasts]
            template = env.get_template('broadcastmessage.html')
            htmldict = render_template(template, user_list, broadcasts)
            dict_html = {"data" : htmldict}
            dict_dump = json.dumps(dict_html)
            return dict_dump

    #Funtion to interface with JS to dynamically refresh page
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def showusers(self):
        user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])

        template = env.get_template('userlist.html')
        htmldict = render_template_user(template, user_list)
        dict_html = {"data" : htmldict}
        dict_dump = json.dumps(dict_html)

        return dict_dump

    #Funtion to interface with JS to dynamically refresh page
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def poll(self):
        user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])

        for user in user_list:
            ip = user['connection_address'] 
            if (user['username'] == "admin"):
                ip="cs302.kiwi.land"
            thread = threading.Thread(target=ping_check, args=(cherrypy.session['username'],cherrypy.session['password'],ip,cherrypy.session['external_ip']))
            thread.start()       
        dict_html = {"data" : ""}
        dict_dump = json.dumps(dict_html)
        print(ip)
        return dict_dump

    #Funtion to interface with JS to dynamically refresh page
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
        cherrypy.session['external_ip'] = main.get_ip_address()+":"+"10050"
        print(cherrypy.session['external_ip'])

        try:
            user_list = list_users(cherrypy.session['username'],cherrypy.session['password'])
            report(cherrypy.session['username'],cherrypy.session['password'])
            test = decrypt_privdata()
            send_dict = json.dumps(user_list)
            #get current private data
            private_data = get_privatedata(cherrypy.session['username'], cherrypy.session['password'])
            private_data_dict = private_data['privatedata']
            cherrypy.session['encrypted_priv']=private_data_dict
            private_data_dict = decrypt_privdata()
            private_data_dict = json.loads(private_data_dict.decode('utf-8'))
            cherrypy.session['temp_privdata'] = private_data_dict
            #show broadcasts
            broadcasts = database.get_broadcast_messages()
            blocked_users = cherrypy.session['temp_privdata']['blocked_usernames']
            temp_broadcasts = []
            for person in blocked_users:
                for broadcast in broadcasts:
                    if(broadcast['loginserver_record'] == person):
                        temp_broadcasts.append(broadcast)
            broadcasts = [x for x in broadcasts if x not in temp_broadcasts]
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
            cherrypy.session['login_success'] = "fail"

            template = env.get_template('loginbutton.html')
            htmld = single_render(template)
            Page += htmld
            
            return Page

    #Broadcast page where user can enter a message    
    @cherrypy.expose
    def broadcast_box(self):
        if (cherrypy.session['login_success'] == "fail"):
            raise cherrypy.HTTPRedirect('/default')
        try:
            template = env.get_template('broadcastbox.html')
            htmld = single_render(template)
            Page = htmld


        except KeyError:
            Page = startHTML + "You have not logged in, please login!<br/>"

        return Page
    #parses the broadcast information and broadcasts to cohort
    @cherrypy.expose
    def get_broadcast(self, broadcast = None):
        if (cherrypy.session['login_success'] == "fail"):
            raise cherrypy.HTTPRedirect('/default')
        try:
            Page = startHTML + "Successfully broadcast a message<br/>"
            cherrypy.session['broadcast'] = broadcast
            poll = list_users(cherrypy.session['username'],cherrypy.session['password'])

            ts = time.time()
            record = cherrypy.session['loginserver_record']
            message_bytes = bytes(record + cherrypy.session['broadcast'] + str(ts), encoding='utf-8')
            signed = cherrypy.session['signing_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
            signature_hex_str = signed.signature.decode('utf-8')
            #threading to support a faster broadcast as parallel threads run faster
            for user in poll:
                ip = user['connection_address'] 
                thread = threading.Thread(target=send_broadcast, args=(cherrypy.session['username'],cherrypy.session['password'],cherrypy.session['broadcast'],ip,record,signature_hex_str))
                thread.start()          
    
            send_broadcast_login(cherrypy.session['username'],cherrypy.session['password'],cherrypy.session['broadcast'])
            Page += "Click here to return to the title <a href='/'>page</a>."

        except KeyError:
            Page = startHTML 
            template = env.get_template('default.html')
            htmld = single_render(template)
            Page += htmld
        except TypeError:
            cherrypy.HTTPRedirect('/')

        return Page
    #Middleman page
    @cherrypy.expose
    def receiver_box(self):
        if (cherrypy.session['login_success'] == "fail"):
            raise cherrypy.HTTPRedirect('/default')
        try:
            
            template = env.get_template('receivebox.html')
            htmld = single_render(template)
            Page = htmld


        except KeyError:
            Page = startHTML + "You have not logged in, please login!<br/>"

        return Page  
    #page for privatemessage
    @cherrypy.expose
    def privatemessage_box(self, Username = None):
        if (cherrypy.session['login_success'] == "fail"):
            raise cherrypy.HTTPRedirect('/default')
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
            Page = startHTML
            template = env.get_template('default.html')
            htmld = single_render(template)
            Page += htmld
        return Page
    #pasring the private message data and sending it to the end user
    @cherrypy.expose
    def send_privatemessage(self, Message = None):
        if (cherrypy.session['login_success'] == "fail"):
            raise cherrypy.HTTPRedirect('/default')
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
            Page = startHTML
            template = env.get_template('default.html')
            htmld = single_render(template)
            Page += htmld
        return Page

    #login page
    @cherrypy.expose
    def login(self, bad_attempt = 0, *vars, **kwargs):
        cherrypy.session['login_success'] = "fail"
        cherrypy.session['filter'] = "off"
        Page = startHTML 
        cherrypy.session['block_broadcasts'] = []
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"

        cherrypy.session['local_ip'] = main.get_ip_address() + ":" + "8000"
        template = env.get_template('firstpage.html')
        
        htmld = single_render(template)
        Page += htmld

        
        
        return Page
    #UNUSED
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
                cherrypy.session['login_success'] = "success"      
                cherrypy.session['status'] = "online"
                report(username, password)
                
                get_record(username,password)
            else:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')      

            cherrypy.session['login_success'] = "success"          
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                
    #signout of the client reporting offline status
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
    #Change the next report status to "away"
    @cherrypy.expose
    def away(self):
        cherrypy.session['status'] = "away"
        raise cherrypy.HTTPRedirect('/')

    #Change the next report status to "online"
    @cherrypy.expose
    def online(self):
        cherrypy.session['status'] = "online"
        raise cherrypy.HTTPRedirect('/')

    #Parse information about who to filter messages from
    @cherrypy.expose
    def block_user(self, Message = None):
        person = Message
        cherrypy.session['temp_person'] = person
        cherrypy.session['filter'] = "on"
        raise cherrypy.HTTPRedirect('/')

    #Parse information about who to block
    @cherrypy.expose
    def block(self):
        try:
            Page =  pageHTML
            template = env.get_template('blockpage.html')
            htmld = single_render(template)
            Page += htmld
            return Page
        except KeyError:
            raise cherrypy.HTTPRedirect('/default')

    #Parse information about what to add to private data end point
    @cherrypy.expose
    def addto_privatedata(self, Message = None):
        try:
            cherrypy.session['temp_privdata']['blocked_usernames'].append(Message)
            add_blockdata(cherrypy.session['username'],cherrypy.session['password'],cherrypy.session['password2'],cherrypy.session['temp_privdata'])
            raise cherrypy.HTTPRedirect('/')

        except KeyError:
            raise cherrypy.HTTPRedirect('/default')


###
### Functions only after here
###

#create a new key pair for user if they request one
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

        
#Return a flag for user successfully logging in
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

#ping the login server with current username and password
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
            
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
    except urllib.error.HTTPError as error:
        print(error.read())

    if (JSON_object["response"] == "ok"):
        print("Ping success")
        return JSON_object
    else:
        print ("Fail")
        return JSON_object

#get private data for the current user.
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
    except urllib.error.HTTPError:
        raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                


#report the current status of the user to the login server
def report(username, password):
    url = "http://cs302.kiwi.land/api/report"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    #cherrypy.session['local_ip']
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
        
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object

    except urllib.error.HTTPError as error:
        print(error.read())

#check the current private key as a login measure
def check_key(username, password):
    try:
        private_data = get_privatedata(username, password)
        private_data_dict = private_data['privatedata']
        cherrypy.session['encrypted_priv']=private_data_dict
        private_data_dict = decrypt_privdata()
        private_data_dict = json.loads(private_data_dict.decode('utf-8'))
        cherrypy.session['temp_privdata'] = private_data_dict
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
     
    except TypeError: 
        raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                

#send a broadcast to a specified person
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

#send a broadcast to the login server   
def send_broadcast_login(username,password,message):
    url = "http://cs302.kiwi.land/api/rx_broadcast"
    # Generate a new random signing key 
    ts = time.time()
    get_record(username,password)
    record = cherrypy.session['loginserver_record']
    message_bytes = bytes(record + message + str(ts), encoding='utf-8')
    signed = cherrypy.session['signing_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
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
    
#get the loginserver record of the person
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
        JSON_object = json.loads(data.decode(encoding))
        cherrypy.session['loginserver_record'] = JSON_object['loginserver_record']
    except urllib.error.HTTPError as error:
        print(error.read())
    except KeyError:
        raise cherrypy.HTTPRedirect('/login?bad_attempt=1')                
     
    except TypeError: 
        raise cherrypy.HTTPRedirect('/login?bad_attempt=1')    


#Calls the list_users api to get everyone who is online    
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
        JSON_object = json.loads(data.decode(encoding))

        return JSON_object['users']
    except urllib.error.HTTPError as error:
        print(error.read())


#send a private message to the specified person
def send_privatemessage(username, password, message):

        

        userlist = list_users(username, password)

        for person in userlist:

            if (person['username'] == cherrypy.session['private_username']):
                target_pubkey = person['incoming_pubkey']
                target_pubkey_bytes = bytes(target_pubkey, 'utf-8')
                thisip = person['connection_address']
                if(cherrypy.session['private_username'] == "admin"):
                    thisip = "cs302.kiwi.land"
                    

        url = "http://"+thisip+"/api/rx_privatemessage"
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
        except urllib.error.HTTPError:
            cherrypy.HTTPRedirect('/index')
        except TimeoutError:
            cherrypy.HTTPRedirect('/index')
        except urllib.error.URLError:
            cherrypy.HTTPRedirect('/index')

#Function to add private data for a specified person
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

#Function to add a person to someone's blocklist. Peoeple on the blocklist will not have their broadcasts seen
def add_blockdata(username, password, password2, private_datas):
    
    ts = str(time.time())

    
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
    print(cherrypy.session['privatekey'])
    signed = cherrypy.session['signing_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
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


#Function to try and decrypt private data using a secret box and an encryption password set by the encryptor of the data
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

#Function to call the ping_check api that regularly checks the health of the server's that are visible to you
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

#------------------------------------------------------------------
#JINJA TEMPLATE RENDERING FUNCTIONS FOR DIFFERENT INPUTS
#------------------------------------------------------------------
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

#Contact an online API to return your external ip. Not used at university but will be used at home for testing purposes
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


