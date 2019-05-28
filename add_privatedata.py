
import cherrypy
import nacl.encoding
import nacl.signing
import base64
import json
import urllib.request
import pprint
import nacl.utils
import time




#STUDENT TO UPDATE THESE...
username = "jyao413"
password = "tigerj2_590856141"
hex_key = b'8cdc1fbb0a2ba92452211c6ffb1b481eaa41024d261d50669b6ebe204a4108f0'
prikeys = "8cdc1fbb0a2ba92452211c6ffb1b481eaa41024d261d50669b6ebe204a4108f0"
blocked_pubkeys = ""
blocked_usernames = "tigerj2"
blocked_message_signatures = ""
blocked_words = ""
favourite_message_signatures = ""
friends_usernames = ""
ts = str(time.time())


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
# Generate a new random signing key
#hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
print(signing_key)


# Sign a message with the signing key

# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Serialize the verify key to send it to a third party
verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
record = "jyao413,4b5ea91f12203c5c8a140d3fac1971799daadb9b8496063ac52b278c0862a9f8,1559047970.3463073,3bea956cbffab35b6e183653a9bf70c7daba8af2497ea4ad111d907bb1db8ee8fb4113c7292aadb1a1a47e6e263e30b9c88e02d4f52be0b08636c3cc92e13207"	

pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex_str = pubkey_hex.decode('utf-8')
print(pubkey_hex_str)
message_bytes = bytes(private_data + record + ts, encoding='utf-8')

signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
signature_hex_str = signed.signature.decode('utf-8')
url = "http://cs302.kiwi.land/api/add_privatedata"

#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

payload = {
    "privatedata" : private_data,
    "loginserver_record" : record,
	"client_saved_at" : ts,
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
