import sqlite3
import urllib
import time
import json

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
                pubkey TEXT,
                message TEXT,
                time TEXT,
                loginrecord TEXT,
                signature TEXT
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
    message_list = [dict['pubkey'],dict['message'],dict['sender_created_at'],dict['loginserver_record'],dict['signature']]
    c.execute("INSERT INTO messages VALUES (?,?,?,?,?)", message_list)
    conn.commit()
    conn.close()
    messages = get_broadcast_messages()
    return messages
#fetches broadcast messages for a certain user's pubkey
def get_broadcast_messages():
    conn = sqlite3.connect('message.db')
    c = conn.cursor()
    c.execute("SELECT * FROM messages")
    
    messages = c.fetchall()
    message_list = []
    for message in messages:
        message_user = message[3].split(',')[0]
        print(float(message[2]))
        float_time = float(message[2])
        real_time = time.ctime(float_time)
        temp_dict = {'pubkey' : message[0], 'message' : message[1], 'sender_created_at' : real_time, 'loginserver_record' : message_user, 'signature' : message[4]}
        message_list.append(temp_dict)

    return message_list

