import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import nacl.utils
import time
from nacl.public import PrivateKey, SealedBox
import unicodedata
url = "http://cs302.kiwi.land/api/rx_privatemessage"

#STUDENT TO UPDATE THESE...
username = "jyao413"
password = "tigerj2_590856141"
target_pubkey = '57dd501613f7acab6a60eed26ff1d94bf8b855bedb5ef301f36ccc5292321abc'
target_user = "admin"
wri = "128151"
message = b'GOni'

# Generate a new random signing key
hex_key = b'37704bcd1690cf848dbca707b02a2b85a918d214785cb8c4b9b1de54faa78d1b'
signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)


# Sign a message with the signing key

# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key


ts = str(time.time())
# Serialize the verify key to send it to a third party
verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex_str = pubkey_hex.decode('utf-8')
pubkey_bytes = bytes(target_pubkey, 'utf-8')
record = 'jyao413,e9d1bb631a5acb9711fb2ea6bbf18e57c1088ae1792276e93bdff7c788010092,1558399771.978730,7ae5bd41a8f14f711ea30f3b2303269c30df452537c3a732317d4e9950d847e046f0d0bf9613759cd328b11314324098549515fe630c1ae9c5d95c6a27f5300a'
print(pubkey_bytes)










privkey = b"243b3d9c9eff76b437d74cb742ec9038c76e15e1b6244644f8f1aa8c670f10d1"
signing_key = nacl.signing.SigningKey(privkey, encoder=nacl.encoding.HexEncoder)

print(signing_key)
verify_key = signing_key.verify_key
print(verify_key)
message = bytes("Hello", 'utf-8')
target_pubkey_bytes = bytes("e8fc12930362c9849989a332e50bb696a588667d89630a8c2025860cc998e447", 'utf-8')
verifykey = nacl.signing.VerifyKey(target_pubkey_bytes, encoder=nacl.encoding.HexEncoder)

publickey = verifykey.to_curve25519_public_key()
sealed_box = nacl.public.SealedBox(publickey)
encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)


curved_privkey = signing_key.to_curve25519_private_key()
mybox = SealedBox(curved_privkey)

messages = mybox.decrypt(encrypted, encoder=nacl.encoding.HexEncoder)
messages_en = messages.decode('utf-8')
print(messages_en)
