#!/usr/bin/python3
""" main.py

    COMPSYS302 - Software Design - Web client
    Current Author/Maintainer: Jason Yao (jyao413@aucklanduni.ac.nz)
    Last Edited: June 2019

    This program uses the CherryPy web server (from www.cherrypy.org).
    This program is a messaging client that interfaces with other messaging
    clients. It was made for our client who wanted a private social network.
    It follows a hybrid communication protocol and is secure and robust
"""
# Requires:  CherryPy 18.0.1  (www.cherrypy.org)
#            Python  (We use 3.5.x +)

import os

import cherrypy

import server

import socket
import api.api

#return socket IP for dynamic IP fetch

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]
# The address we listen for connections onw
LISTEN_IP = get_ip_address()
LISTEN_PORT = 10050

#Main application to start server and mount server 
def runMainApp():
    #set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.getcwd(),
            'tools.encode.on': True, 
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout': 60 * 1, #timeout is in minutes, * 60 to get hours


            # The default session backend is in RAM. Other options are 'file',
            # 'postgres', 'memcached'. For example, uncomment:
            # 'tools.sessions.storage_type': 'file',
            # 'tools.sessions.storage_path': '/tmp/mysessions',
        },

        #configuration for the static assets directory
        '/static': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        },

        
        #once a favicon is set up, the following code could be used to select it for cherrypy
        #'/favicon.ico': {
        #    'tools.staticfile.on': True,
        #    'tools.staticfile.filename': os.getcwd() + '/static/favicon.ico',
        #},
    }

    cherrypy.site = {
        'base_path': os.getcwd()
    }

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(server.MainApp(), "/", conf)
    # Create an instance of Api to tell Cherrypy to send all requests under /api to it. 
    cherrypy.tree.mount(api.api.Api(), "/api", conf)


    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({'server.socket_host': LISTEN_IP,
                            'server.socket_port': LISTEN_PORT,
                            'engine.autoreload.on': True,
                           })

    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)

    print("========================================")
    print("             Jason Yao")
    print("         University of Auckland")
    print("   COMPSYS302 - Twitter client web app")
    print("========================================")                       
    
    # Start the web server
    cherrypy.engine.start()
    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything.
if __name__ == '__main__':
    runMainApp()
