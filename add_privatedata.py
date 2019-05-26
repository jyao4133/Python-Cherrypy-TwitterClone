
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
hex_key = b'37704bcd1690cf848dbca707b02a2b85a918d214785cb8c4b9b1de54faa78d1b'
prikeys = ""
blocked_pubkeys = ""
blocked_usernames = "tigerj2"
blocked_message_signatures = ""
blocked_words = ""
favourite_message_signatures = ""
friends_usernames = ""
ts = str(time.time())

private_data = prikeys + blocked_pubkeys + blocked_usernames + blocked_message_signatures + blocked_words + favourite_message_signatures + friends_usernames
# Generate a new random signing key
#hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
print(hex_key)


# Sign a message with the signing key

# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Serialize the verify key to send it to a third party
verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
record = "jyao413,e9d1bb631a5acb9711fb2ea6bbf18e57c1088ae1792276e93bdff7c788010092,1558399771.978730,7ae5bd41a8f14f711ea30f3b2303269c30df452537c3a732317d4e9950d847e046f0d0bf9613759cd328b11314324098549515fe630c1ae9c5d95c6a27f5300a"	

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
