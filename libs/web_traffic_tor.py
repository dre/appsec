"""
    Author: Andres Andreu
    Company: neuroFuzz, LLC
    Date: 11/1/2012
    Last Modified: 11/2/2012
    Prog to perform a distributed set of GET requests
    against a given target web server across multiple
    randomly chosen SOCKS5 sockets leveraging tor

    MIT-LICENSE
    Copyright (c) 2012 - 2013 Andres Andreu, neuroFuzz LLC
    
    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
    
    If you use this for criminal purposes and get caught you are on
    your own and I am not liable. I wrote this for legit pen testing
    purposes.
    
    Be kewl and give credit where it is due if you use this. Also,
    send me feedback as I don't have the bandwidth to test for every
    condition.    
"""
from random import choice
from threading import Thread
from vars import web_traffic_tor_vars
from time import sleep
import funcs
import getopt
import math
import os
import random
import re
import signal
import socks
import string
import sys

class httpGet(Thread):
    def __init__(self, host="", port="", sleepTime="") :
        self.host = host
        self.port = port
        self.sleepTime = sleepTime
        self.hostheader = host
        self.torip = web_traffic_tor_vars.getTorIp()
        sr = web_traffic_tor_vars.getSleepBounds()
        self.sleepRange = [sr[0], sr[1]]
        self.stopped = False
        self.torportlist = []
        self.verbs = ['GET', 'HEAD']
        self.anonimize = True
        Thread.__init__(self)
        
    def setAnonimize(self, val=True):
        self.anonimize = val

    def setTorPortList(self, plist=[]):
        self.torportlist = plist
        
    def setHost(self, val=""):
        self.host = val
        
    def setHostHeader(self, val=""):
        self.hostheader = val
        
    def setPort(self, val=""):
        self.port = val

    def stop(self):
        self.stopped = True

    def run(self):
        sleep(choice(self.sleepRange))
        while not self.stopped:
            try:
                sleep(choice(self.sleepRange))
                s = socks.socksocket()
                if self.anonimize:
                    s.setproxy(socks.PROXY_TYPE_SOCKS5, self.torip, int(choice(self.torportlist)))
                s.connect((self.host, self.port))
                s.settimeout(1)
                turi = choice(['/', funcs.createRandAlpha(length=random.randint(1,20))])
                if turi != '/':
                    turi = '/' + turi
                    if choice([True,False]):
                        turi = turi + "." + choice(['html', 'htm', 'php', 'aspx', 'cfm'])
                s.send("%s %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "User-Agent: %s\r\n\r\n" % 
                       (choice(self.verbs), turi, self.hostheader, funcs.getRandUserAgent())
                       )
                s.close
            except Exception, e:
                #print e.args
                sleep(1)
                continue

def kickOff(host="", port="", uri="", plist=[]) :
    setHhdr = False
    threads = web_traffic_tor_vars.getThreads()
    sleepTime = web_traffic_tor_vars.getSleepTime()
    
    host = host or web_traffic_tor_vars.getHost()
    port = port or web_traffic_tor_vars.getPort()
    uri = uri or web_traffic_tor_vars.getUri()
        
    hhdr = web_traffic_tor_vars.getHostHeader()
    if hhdr:
        setHhdr = True

    tpool = []
    try:
        for i in range(1, threads):
            t = httpGet(host, port, sleepTime)
            if len(plist) > 0:
                t.setTorPortList(plist=plist)
            if setHhdr:
                t.setHostHeader(val=hhdr)
            tpool.append(t)
            t.start()
        while True:
            sleep(choice(range(1,10)))

    except KeyboardInterrupt, e:
        print "\nKeyboard Interruption ... stopping all threads"
        for h in tpool:
            h.stop()
        for h in tpool:
            h.join()

def killThreads(ppid=0):
    print "Killing threads... ",
    os.kill(int(ppid), signal.SIGTERM)
    print "\n"
