"""
    Author: Andres Andreu
    Company: neuroFuzz, LLC
    Date: 10/10/2012
    Last Modified: 11/22/2012
    Prog written to do recon discovery of virtual hosts
    against a given target web server.

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
from datetime import datetime, timedelta
from libs import AntiIDS, SocketController, funcs, httplib2, slow_ddos_tor, web_traffic_tor
from vars import vhost_finder_vars
from random import choice, shuffle
from string import digits, letters
from urlparse import urlparse
import Queue
import threading
import itertools
import multiprocessing
import os
import random
import re
import socket
import time
import sys
import glob

# vars
debug = vhost_finder_vars.getVHostDebug()
anonimize = vhost_finder_vars.getAnonimize()
displayThreshold = vhost_finder_vars.getDisplayThreshold()
failedHosts = []
random.seed()

if anonimize:
    sc = SocketController.SocketController()
    sc.spawnSockets()

class Counter:
    def __init__(self):
        self.lock = threading.Lock()
        self.value = 0
        self.total = 0
        self.outPoint = 0

    def increment(self):
        self.lock.acquire() # critical section
        self.value = self.value + 1
        self.lock.release()
        return self.value
    def add(self,value):
        self.lock.acquire() # critical section
        self.value = self.value + value
        self.lock.release()
        return self.value
    
    def setTotal(self, total=0):
        self.total = total
        if total < 2000:
            self.outPoint = int((1.0 * total / 400) * 100)
        else:
            self.outPoint = 2000
        
    def getTotal(self):
        return self.total
    
    def getOutPoint(self):
        return self.outPoint

class ThreadUrl(threading.Thread):
    ''' Threaded Url Grab '''
    def __init__(self, queue,foundvhosts, ipAddress,port,baseline,counter):
        threading.Thread.__init__(self)
        self.queue = queue
        self.foundvhosts = foundvhosts
        self.ipAddress = ipAddress
        self.port = port
        self.baseline = baseline
        self.counter = counter
        self.localcounter = 0
        #possibly remove Location from baseline, might not be accurate
        self.includeinbaseline = ['HTTP','Server','Content-Type','Content-Length','Location']
    
    def run(self):
        while True:
            c = None
            '''
                grabs host from queue
                will cause exception if there are no items in queue
                and more then 10 sec have passed, 
                this will break out of while loop
            '''
            host = self.queue.get()
            if debug:
                print "Trying Host: %s" % host
            try:
                '''
                    rand sleep and then some socket
                    choice randomness with the Tor
                    sockets
                '''
                time.sleep(choice(range(1,30)))
                if anonimize:
                    if funcs.getRandBool() == True:
                        c = sc.setSocksProx()
                    else:
                        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    
                if not c:
                    c = sc.setSocksProx()
                    if not c:
                        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # connect to the socket 
                c.connect((self.ipAddress, int(self.port)))
                # request line
                http_data = funcs.constructRequest(target=host, resource="/")
                c.send(http_data)
                data = c.recv(1024*5)
                c.close()
                response_code = data.split(" ")[1]
                
                if debug:    
                    print "Host target: " + host
                    print http_data
                    print data
                    print "Response Code:" + response_code   
                    print "Baseline Hash: %s" % self.baseline
                    print "Current Hash: %s" % funcs.stripheader(data,self.includeinbaseline)
                
                if funcs.stripheader(data,self.includeinbaseline) != self.baseline:
                    if debug:
                        print "I think this exists: %s" % host
                        print data
                    if host not in self.foundvhosts:
                        self.foundvhosts.append(host)

                val = self.counter.add(1)
                if val % self.counter.getOutPoint() == 0:
                    print "Tested %s vhosts, last checked: '%s' - %s %s" % (str(val),host, 
                                                                            '-'.join(funcs.getTimeStamp().split('.')[0:3]),
                                                                            ':'.join(funcs.getTimeStamp().split('.')[3:]))
            except socket.error, err:
                if c:
                    c.close()
                if debug:
                    print err
                    print "failed for host %s" % host
                failedHosts.append(host)
            except IndexError, err:
                if c:
                    c.close()
                if debug:
                    print err
                    print "failed for host %s" % host
                failedHosts.append(host)
            #signals to queue that job is done    
            self.queue.task_done()
                
class VHostFinder:
    # constructor
    def __init__(self, ipAddress=None):
        if ipAddress:
            self.ipAddress = ipAddress
            self.domain = ""
            self.tld = ""
            self.request_headers = {}
            self.baseline = ""
            self.port = 0
            self.low = 1  #range of bruteforce
            self.high = 3
            self.queue = Queue.Queue()
            self.foundvhosts = []
            self.totalthreads = 1
            self.counter = Counter()
            
            self.h = httplib2.Http(cache = None, timeout = 6, proxy_info = None)
            self.h.follow_redirects = False
            
            self.elements = ['internal','external', 'www', 'crap', 'collab', 'dvwa','mysite']
           
            self.good_ones = ['404', '403']
            self.bad_ones = []
            #headers to include in baseline, location might not be a good idea
            self.includeinbaseline = ['HTTP','Server','Content-Type','Content-Length','Location']
            self.redirect_targets = []
            self.totalHostsToTry = 0
            
    def setIPAddress(self, ip=""):
        if ip:
            self.ipAddress = ip
    
    def setTotalThreads(self, totalthreads=1):
        if totalthreads:
            self.totalthreads = totalthreads
            
    def setPort(self, port=80):
        if port:
            self.port = port
    def setDepth(self, low=1,high=5):
        if low:
            self.low = low
        if high:
            self.high = high
            
    def setDomain(self, domain=""):
        if domain:
            self.domain = domain
    
    def setElements(self, elements=""):
        if debug:
            print "Setting elements ... ",
        if elements:
            self.elements = elements
        else:
            self.elements = map(chr, range(97, 123))
        if debug:
            print self.elements
            
    def setTld(self, tld=""):
        if tld:
            self.tld = tld
            
    def addRequestHeader(self, key="", val=""):
        self.request_headers[key] = val
    
    def setBaseLine(self):
        ''' get a baseline for a bad request '''
        try:
            print "\nSetting baseline ...",
            """
                numbers are valid characters in a domain,
                assuming no one would set the below domain
                as a given vhost of a server (even though that
                would be interesting) ...
                therefore we assume this will produce a 
                "vhost does not exist on this server" response
                TODO: form a large random number to replace the static one below
            """
            http_data = funcs.constructRequest(verb="GET", target="314159265358979323846264338327950288." + self.domain + "." + self.tld, resource="/")
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect((self.ipAddress, self.port))
            c.send(http_data)
            data = c.recv(1024*5)
            c.close()
            if debug:
                print http_data
                print data
            
            self.baseline = funcs.stripheader(data,self.includeinbaseline)
            print self.baseline
        except:
            print "\nError connecting, cleaning up\n\n"
            # kill tor sockets we spun up
            if anonimize:
                '''
                for p in sc.getTorPids():
                    funcs.killPid(ppid=p)
                '''
                for dir,_,_ in os.walk(sc.getDataDir()):
                    pidHandle = glob.glob(os.path.join(dir,'tor*.pid'))
                    if pidHandle:
                        funcs.killPid(ppid=int(open(pidHandle[0]).readline()))
                print
            slow_ddos_tor.killThreads()
            print
            sys.exit(0)
            

    def probeVhosts(self):
        #status_match = re.compile("HTTP/1.[1|0] (\d)* (\w)*")
        vhosts = []
        """
            start the threads
            populate the queue
            wait for join
        """
        for i in range(self.totalthreads):
            t = ThreadUrl(self.queue,self.foundvhosts,self.ipAddress,self.port,self.baseline,self.counter)
            t.setDaemon(True)
            t.start()
        
        for r in range(self.low,self.high + 1):
            '''
                set the data in some random order
                so as to give those pattern analysis
                algorithms some fun in discovering
                our behavior
            '''
            shuffle(self.elements)
            #generates iterator with given dictionary of "r" depth
            for vhost in itertools.product(self.elements,repeat=r):
                vhosts.append("".join(vhost))
            self.totalHostsToTry = len(vhosts)
            self.counter.setTotal(total=self.totalHostsToTry)
            if r == self.high:
                print "\nTotal hosts to try: %d\n" % self.totalHostsToTry

            #for vhost in itertools.product(self.elements,repeat=r):
            for vhost in vhosts:
                #targ = "".join(vhost) + "." + self.domain + "." + self.tld
                targ = vhost + "." + self.domain + "." + self.tld
                self.queue.put(targ)

        #wait for queue of hosts to be empty
        self.queue.join()
        '''
            if any timeouts caused failures to 
            check specific hosts the list 'failedHosts'
            will hold them so process if there are any
            values in the list
        '''
        if len(failedHosts) > 0:
            for i in range(self.totalthreads):
                t = ThreadUrl(self.queue,self.foundvhosts,self.ipAddress,self.port,self.baseline,self.counter)
                t.setDaemon(True)
                t.start()

            for vhost in failedHosts:
                if debug:
                    print "Processing failed host: %s" % vhost
                self.queue.put(vhost)
            self.queue.join()
        
        print "\nResults: ...\n"
        if len(self.foundvhosts) > 0:
            for v in self.foundvhosts:
                funcs.outStatement(val=v, result="Good")
                #print v
        else:
            print "Nothing discovered"
        
def setItOff(host="", port="", domain="", tld=""):
    name = multiprocessing.current_process().name
    setitpid = os.getpid()
    print name + " Started with pid %d" % setitpid

    vhf = VHostFinder(host)
    vhf.setPort(port)
    vhf.setDomain(domain)
    vhf.setTld(tld)
    vhf.setElements()
    bnds = vhost_finder_vars.getDepthBounds()
    vhf.setDepth(bnds[0],bnds[1])
    vhf.setTotalThreads(vhost_finder_vars.getVHostNumThreads())
    vhf.setBaseLine()
    vhf.probeVhosts()

    print "\n" + name + " Finished"
    finish = time.time()
    funcs.sec_to_time(sec=(finish - start))

    # kill tor sockets we spun up
    if anonimize:
        for dir,_,_ in os.walk(sc.getDataDir()):
            pidHandle = glob.glob(os.path.join(dir,'tor*.pid'))
            if pidHandle:
                funcs.killPid(ppid=int(open(pidHandle[0]).readline()))
        print
    # kill DDoS threads
    slow_ddos_tor.killThreads()
    print
    
def setOffSlowDos(host="", port=""):
    name = multiprocessing.current_process().name
    slowdospid = os.getpid()
    print "\n\n" +  name + " Started with pid %d" % slowdospid
    slow_ddos_tor.kickOff(host=host, port=port, plist=sc.getPortList())
    print name + " Finished - %s" % name
    
def setOffGets(host="", port=""):
    name = multiprocessing.current_process().name
    webtrafficpid = os.getpid()
    print "\n\n" +  name + " Started with pid %d" % webtrafficpid
    web_traffic_tor.kickOff(host=host, port=port, plist=sc.getPortList())
    print name + " Finished - %s" % name

if __name__ == "__main__":
    start = time.time()
    
    tip = vhost_finder_vars.getTargetIp()
    tport = vhost_finder_vars.getTargetPort()
    tdomain = vhost_finder_vars.getTargetDomain()
    ttld = vhost_finder_vars.getTargetTld()
    slowdos = vhost_finder_vars.getUseSlowDoS()

    if slowdos:
        worker_slowDos = multiprocessing.Process(name='Slow Dos Attack', target=setOffSlowDos, args=(tip,tport))
        worker_slowDos.start()
        
    worker_Get = multiprocessing.Process(name='Just Get', target=setOffGets, args=(tip,tport))
    worker_Get.start()
    
    worker_vHostFind = multiprocessing.Process(name='VHost Finder', target=setItOff, args=(tip,tport,tdomain,ttld))
    worker_vHostFind.start()

