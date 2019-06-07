import sqlite3
import urllib
import time
import json
from nacl.public import PrivateKey, SealedBox
import nacl.encoding
import nacl.signing
import base64
import urllib.request
import pprint
import nacl.utils

def createDB_userlist():

    conn = sqlite3.connect('userdb.db')
    c = conn.cursor()
    #create table
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                ip TEXT,
                username TEXT
                )""")


    conn.commit()
    conn.close()

def createDB_messagedata():
    conn = sqlite3.connect('message.db')
    c = conn.cursor()
    #create table
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                message TEXT,
                time TEXT,
                loginrecord TEXT,
                signature TEXT
                )""")


    conn.commit()
    conn.close()
def createDB_pmdata():
    conn = sqlite3.connect('pm.db')
    c = conn.cursor()
    #create table
    c.execute("""CREATE TABLE IF NOT EXISTS pms (
                target_pubkey TEXT,
                message TEXT,
                time TEXT,
                loginrecord TEXT,
                signature TEXT,
                target_username TEXT
                )""")


    conn.commit()
    conn.close()

def createDB_senderdata():
    conn = sqlite3.connect('sentpm.db')
    c = conn.cursor()
    #create table
    c.execute("""CREATE TABLE IF NOT EXISTS sentpms (
                message TEXT,
                time TEXT,
                target_username TEXT,
                current_username TEXT
                )""")


    conn.commit()
    conn.close()
def addtoDB_user(dict):

    conn = sqlite3.connect('userdb.db')
    c = conn.cursor()
    c.execute("INSERT INTO users VALUES (?,?)", (dict['ip_address'],dict['username']))
    conn.commit()
    c.execute("SELECT * FROM users WHERE ip='tigerj2'")
    print(c.fetchall())

    conn.close()

def addtoDB_broadcast(dict):
    conn = sqlite3.connect('message.db')
    c = conn.cursor()
    message_list = [dict['message'],dict['sender_created_at'],dict['loginserver_record'],dict['signature']]
    c.execute("INSERT INTO messages VALUES (?,?,?,?)", message_list)
    conn.commit()
    conn.close()
    messages = get_broadcast_messages()
    return messages

def addtoDB_pms(dict):
    conn = sqlite3.connect('pm.db')
    c = conn.cursor()
    message_list = [dict['target_pubkey'],dict['encrypted_message'],dict['sender_created_at'],dict['loginserver_record'],dict['signature'],dict['target_username']]
    c.execute("INSERT INTO pms VALUES (?,?,?,?,?,?)", message_list)
    conn.commit()
    conn.close()


def addtoDB_sentpms(dict):
    conn = sqlite3.connect('sentpm.db')
    c = conn.cursor()
    message_list = [dict['message'],dict['sender_created_at'],dict['target_username'], dict['current_username']]
    c.execute("INSERT INTO sentpms VALUES (?,?,?,?)", message_list)
    conn.commit()
    conn.close()


#fetches broadcast messages
def get_broadcast_messages():
    conn = sqlite3.connect('message.db')
    c = conn.cursor()
    c.execute("SELECT * FROM messages")
    
    messages = c.fetchall()
    message_list = []
    for message in messages:
        message_user = message[2].split(',')[0]
        try:
            float_time = float(message[1])
            real_time = time.ctime(float_time)
        except KeyError:
            real_time = "Undefined time"
            
        temp_dict = {'message' : message[0], 'sender_created_at' : real_time, 'loginserver_record' : message_user, 'signature' : message[3]}
        message_list.append(temp_dict)

    return message_list
#database for pms received, called in rx_privatemessage
def get_pms(current_user, privkey):
    conn = sqlite3.connect('pm.db')
    c = conn.cursor()
    
    pm_list = []
    c.execute("SELECT * FROM pms WHERE target_username=?", (current_user,))
    messages = c.fetchall()

    for message in messages:
        #convert into actual time format
        float_time = float(message[2])
        real_time = time.ctime(float_time)    
        message_user = message[3].split(',')[0]
        unencrypted_message = decrypt_pm(privkey, message[1])
        temp_dict = {'target_pubkey' : message[0], 'encrypted_message' :unencrypted_message, 'sender_created_at' : real_time, 
        'loginserver_record' : message[3], 'signature' : message[4], 'target_username' : message[5], 'sender' : message_user}
        pm_list.append(temp_dict)

    print(pm_list)
    return pm_list
#database for pms sent, called in server side 
def get_sentpms(target_user):

    conn = sqlite3.connect('sentpm.db')
    c = conn.cursor()
    
    pm_list = []
    c.execute("SELECT * FROM sentpms WHERE target_username=?", (target_user,))
    messages = c.fetchall()
    print(messages)
    for message in messages:
        #convert into actual time format
        float_time = float(message[1])
        real_time = time.ctime(float_time)    
        temp_dict = {'message' : message[0], 'sender_created_at' : real_time, 
        'target_username' : message[2], 'sender' : message[3]}

        pm_list.append(temp_dict)

    print(pm_list)
    return pm_list
def decrypt_pm(privkey, message):
    
    curved_privkey = privkey.to_curve25519_private_key()
    mybox = SealedBox(curved_privkey)

    messages = mybox.decrypt(message, encoder=nacl.encoding.HexEncoder)
    messages_en = messages.decode('utf-8')

    return messages_en