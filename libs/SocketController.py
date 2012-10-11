"""
    Author: Andres Andreu
    Company: neuroFuzz, LLC
    Date: 10/10/2012
    Prog to spawn off a number of instances of tor

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
import socks
import socket
import subprocess
from random import choice

class SocketController:
    def __init__(self):
        self.torpath = "/Applications/Vidalia.app/Contents/MacOS/tor"
        self.base_socks_port = 9052
        self.base_control_port = 8120
        self.socks_control_ports = {}
        self.socks_port_list = []
        self.datadir = '/Users/andresandreu/software_engineering/appsec/recon/vhost_finder/tordata'
        self.torfname = 'tor%sfile'
        self.torarguments = {"--RunAsDaemon":'1',
                             "--CookieAuthentication":'0',
                             "--HashedControlPassword":'',
                             "--ControlPort":'%s',
                             "--PidFile":'tor%s.pid',
                             "--SocksPort":'%s',
                             "--DataDirectory":self.datadir + '/tor%s'
                             }
        self.torSocketLowerBound = 1
        self.torSocketUpperBound = 5
        self.lastProxUsed = 0
        self.debug = False
        self.selfip = '127.0.0.1'
        socket.setdefaulttimeout(10)
        
    def getPortList(self):
        return self.socks_port_list
        
    def setLowerBound(self, val=""):
        self.torSocketLowerBound = val
        
    def setUpperBound(self, val=""):
        self.torSocketUpperBound = val
        
    def setLastUsed(self, val=""):
        self.lastProxUsed = val
        
    def getLastUsed(self):
        return self.lastProxUsed
    
    def setDebug(self, val=""):
        self.debug = val
        
    def spawnSockets(self):
        '''
            kick off a pool of tor instances
            because each one will have a different
            path to the target. Had to do it this way
            because once we are using a tor socks prox
            the calls to localhost to refresh the
            tor identity will obviously crap out
        '''
        for i in range(self.torSocketLowerBound,self.torSocketUpperBound):
            '''
                first create data file
                Simply opening a file in write mode will create it, if it doesn't exist. 
                If the file does exist, the act of opening it in write mode will completely
                overwrite its contents
            '''
            fname = self.torfname % str(i)
            try:
                if self.debug:
                    print self.datadir + '/tor' + str(i) + '/' + fname
                f = open(self.datadir + '/tor' + str(i) + '/' + fname, "w")
            except IOError:
                pass
            
            runstmt = []
            runstmt.append(self.torpath)
            
            bsp = str(self.base_socks_port+i)
            bcp = str(self.base_control_port+i)
            self.socks_control_ports[bsp] = bcp
            self.socks_port_list.append(bsp)
            
            for k in self.torarguments.iterkeys():
                if k == '--ControlPort':
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k] % bcp)
                elif k == '--PidFile':
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k] % str(i))
                elif k == '--SocksPort':
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k] % bsp)
                elif k == '--DataDirectory':
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k] % str(i))
                else:
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k])
            
            if self.debug:
                print "\n"
                print runstmt
                print "\n"

            '''
                notes:
                
                tor --RunAsDaemon 1 
                    --CookieAuthentication 0 
                    --HashedControlPassword "" 
                    --ControlPort 8124
                    --PidFile tor4.pid 
                    --SocksPort 9056 
                    --DataDirectory data/tor4
            '''
            subprocess.Popen(runstmt)
            
    def setSocksProx(self):
        prot = int(choice(self.socks_port_list))
        if prot != self.getLastUsed():
            if self.debug:
                print "\nSwitching SOCKS prox to ip %s, port: %d" % (self.selfip,prot)
            s = socks.socksocket()
            if s:
                s.setproxy(proxytype=socks.PROXY_TYPE_SOCKS5, addr=self.selfip, port=prot)
                self.setLastUsed(val=prot)
                return s
        return None
