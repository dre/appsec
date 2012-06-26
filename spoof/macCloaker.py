"""
    Author:     Andres Andreu
    Contact:    <andres [at] neurofuzz dot com>
    Company:    neuroFuzz, LLC
    Date:       6/23/2012
    Modified:   6/25/2012
    
    This software runs on certain flavors of Linux and
    Mac OSX (written on 10.7.x with python 2.6/2.7). 
    Its intent is to temporarily change/spoof the 
    MAC Address on the machine running it.
    
    It leverages macchanger if it is found but
    works just as well without it. I happen
    to think macchanger is great software so
    props to Alvaro Lopez Ortega <alvaro [at] alobbs dot com>
    for writing it (http://www.alobbs.com/macchanger).
    But I needed something a little more automated 
    and that could be used as an API from other 
    py progs while conducting security audit work and/or
    pen testing stuff.
    
    The code I did see out there that operates on this same
    functionality just lacked so much and made so many static
    and bad assumptions that I decided to just write this 
    myself. So in the spirit of open source I am sharing this
    with the world.
    
    Usage:
    
    sudo python macCloaker.py
    
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
"""
import os
import fnmatch
import signal
import commands
import sys
import random
import subprocess
import re
import datetime
import time
import platform


class MacCloak(object):

    # constructor
    def __init__(self):
        self.targetInterface = ""
        self.originalMacAddress = ""
        self.fakeMacAddress = ""
        self.persistFile = ".originalMac"
        self.lineFormatString = '%s\t%s\t#%d#%s\n'
        self.defaultProg = self.which(program="ifconfig")
        self.alternateProg = "macchanger"
        self.runningPlatform, self.runningPlatformFlavor = self.discoverPlatform()
        self.dhcpUsed = False
        
    def setInterface(self, iface=""):
        self.targetInterface = iface
        
    def setOriginalMacAddress(self, mac=""):
        self.originalMacAddress = mac
        
    def getInterface(self):
        return self.targetInterface
        
    def getOriginalMacAddress(self):
        return self.originalMacAddress

    def setFakeMacAddress(self, val=""):
        self.fakeMacAddress = val
        
    def getFakeMacAddress(self):
        return self.fakeMacAddress
    
    def getRunningPlatform(self):
        ''' fethces lowercase string identifying the running OS '''
        return self.runningPlatform
    
    def getRunningPlatformFlavor(self):
        ''' fethces string identifying more granular aspects of a Linux OS '''
        return self.runningPlatformFlavor
    
    def amIRoot(self):
        """ checks to see if running user has root privileges """
        if os.geteuid() != 0:
            print("You need to be root to do this ...")
            return False
        else:
            return True

    def randomMAC(self):
        """ generates random MAC Address """
        mac = [random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff)]
        return (':'.join(map(lambda x: "%02x" % x, mac)))

    def runOsProcess(self, lParams=[]):
        """ run system level processes """
        co = subprocess.Popen(lParams, stdout = subprocess.PIPE)
        return co.stdout.read().split()
            
    def findFile(self, pattern="", root='/'):
        print "Searching for ... %s" % pattern
        matches = []
 
        for path, dirs, files in os.walk(os.path.abspath(root)):
            for filename in fnmatch.filter(files, pattern):
                matches.append(os.path.join(path, filename))
     
        return matches
            
    def which(self, program=""):
        ''' find location of executable code '''
        def is_exe(fpath):
            return os.path.exists(fpath) and os.access(fpath, os.X_OK)
    
        def ext_candidates(fpath):
            yield fpath
            for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
                yield fpath + ext
    
        fpath, fname = os.path.split(program)
        if fpath:
            if is_exe(program):
                return program
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                exe_file = os.path.join(path, program)
                for candidate in ext_candidates(exe_file):
                    if is_exe(candidate):
                        return candidate
        return None

    def modMac(self, randomly=False):
        """ kicks off the change MAC Address process """

        """
            if randomly is set to False then that
            means the request is being made to
            reset the Mac Address to its original
            state
        """
        if randomly == False:
            self.useIfconfig(randomly=randomly)
        else:
            """
                cannot assume that macchanger will only
                exist in one location so let's look
                for it
            """
            if self.which(program=self.alternateProg) != None:
                print("MAC Changer is installed, using it...")
                self.useMacchanger()
            else:
                print("MAC Changer is not installed, using ifconfig method!")
                self.useIfconfig(randomly=randomly)
            
    def modInterfaceState(self, thestate="up"):
        ''' modify interface state up/down '''
        dhcpused = False
        
        if thestate == "down":
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, thestate])
        """
            bringing the interface up is not
            enough if DHCP is in use. modInterfaceState
            has code to handle this use case
            when the 'up' value is passed in
            to the parameter thestate
        """
        if thestate == "up":
            # bring interface up
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, thestate])
            """
                if dhcp is used then restart client ...
                if we only bring up the interface and
                dont renew dhclient lease then full
                network connectivity is not restored
            """
            if self.dhcpUsed:
                self.handleDhcpReset()

        # check result by running ifconfig
        procOut = self.runOsProcess(lParams=[self.defaultProg])
        # process failed, interface still up
        if self.targetInterface in procOut:
            return False
        return True
    
    def readFile(self, fhandle=""):
        try:
            f = open(fhandle, 'r')
            fcontent = f.readlines()
            f.close()
            return fcontent
        except Exception, e:
            print e
 
    def useMacchanger(self):
        ''' us macchanger to take action on the interface '''
        
        print("[+] Changing your original MAC address (%s) to something totally random..." % self.getOriginalMacAddress())
        macchanger = self.which(program="macchanger")
        
        # Puts interface down
        if self.modInterfaceState(thestate='down'):
            print("[*] Interface is %s" % 'down')
        time.sleep(6)
        # change the MAC Address
        poutput = self.runOsProcess(lParams=[macchanger, "--random", self.targetInterface])
        
        self.setFakeMacAddress(val=poutput[poutput.index("Faked")+2])
        # Puts interface up
        if self.modInterfaceState(thestate='up'):
            print("[*] Interface is %s" % 'up')
        time.sleep(10)
 
    def useIfconfig(self, randomly=False):
        ''' us ifconfig to take action on the interface '''
        """
            either randomly or back to normal
        """
        if randomly == True:
            #os.popen("ifconfig " + self.targetInterface + " hw ether " + randomMAC())
            randVal = self.randomMAC()
            self.setFakeMacAddress(val=randVal)
            print("[+] Changing your original MAC address (%s) to something totally random..." % self.getOriginalMacAddress())
            
            # on Linux - ifconfig en1 hw ether 00:e2:e3:e4:e5:e6
            if self.getRunningPlatform() == "linux":
                self.processLinux(randVal=randVal)    
            # on Mac OSX - ifconfig en1 ether 00:e2:e3:e4:e5:e6
            if self.getRunningPlatform() == "darwin":
                self.processDarwin(randVal=randVal)
        else:
            """
                this section sets the MAC Address back
                to its normal and original setting
            """
            print("[+] Changing your MAC address to its original value ... %s") % self.originalMacAddress
            # on Linux
            if self.getRunningPlatform() == "linux":
                self.processLinux()
            # on Mac OSX 
            if self.getRunningPlatform() == "darwin":
                self.processDarwin()
                
    def processLinux(self, randVal=None):
        ''' set MAC Address back to original state on Linux'''
        # Puts interface down
        if self.modInterfaceState(thestate='down'):
            print("[*] Interface is %s" % 'down')
        time.sleep(6)
        # change the MAC Address
        if randVal != None:
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, 
                                       "hw", "ether", randVal])
        else:
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, 
                                       "hw", "ether", self.originalMacAddress])
        
        # Puts interface up
        if self.modInterfaceState(thestate='up'):
            print("[*] Interface is %s" % 'up')
        time.sleep(10)
        
    def processDarwin(self, randVal=None):
        ''' set MAC Address back to original state on Mac OSX '''
        # change the MAC Address
        if randVal != None:
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, 
                                       "ether", randVal])
        else:
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, 
                                       "ether", self.originalMacAddress])
        time.sleep(2)
        # Puts interface down
        if self.modInterfaceState(thestate='down'):
            print("[*] Interface is %s" % 'down')
        time.sleep(6)
        # Puts interface up
        if self.modInterfaceState(thestate='up'):
            print("[*] Interface is %s" % 'up')
        time.sleep(10)
        self.handleDhcpReset()
        
    def persistData(self):
        ''' save the current MAC Address data out to a file '''
        try:
            macs = open(self.persistFile, 'a')
            macs.write(self.lineFormatString % (self.targetInterface,
                                                self.originalMacAddress,
                                                os.getpid(), datetime.datetime.now().isoformat()))
            macs.close()
        except Exception, e:
            print e
            if 'denied' in str(e):
                self.shutDown(s="You do not have enough permissions to modify " + self.persistFile) 

    def getIface(self):
        """ extracts a list of system interfaces for user to choose from """
        theinterface = ""
        wecontinue = False

        if os.name == "posix":
            co = subprocess.Popen(self.defaultProg, stdout = subprocess.PIPE)
            ifconfig = co.stdout.read()
            thechoices = None
        
            print "\nPick an interface to mess with:\n"

            if self.getRunningPlatform() == 'darwin':
                #thechoices = re.findall(r'^([\w]*):? [\w=<,>\s]*(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', ifconfig, re.MULTILINE)
                thechoices = re.findall(r'^([\w]*):? [\w=<,>\s]*(([0-9a-fA-F]{2}:?){6})', ifconfig, re.MULTILINE)
            """
                this regex was tested with Fedora and Debian ...
                not sure if it will actually work with every flavor of Linux
            """
            if self.getRunningPlatform() == 'linux':
                #thechoices = re.findall(r'^([\w]*):? [\w=<,>:.\s]*(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', ifconfig, re.MULTILINE)
                thechoices = re.findall(r'^([\w]*):? [\w=<,>:.\s]*(([0-9a-fA-F]{2}:?){6})', ifconfig, re.MULTILINE)    
            """
                if not interfaces are discovered then
                there is no need to go any further
            """
            if thechoices != None:
                for f in thechoices:
                    if not f[1].endswith(":"):
                        print "%s %s" % (f[0], f[1])
            else:
                print "No interfaces discovered, help us out and send us this data via email ..."
                print "\n\n###########################"
                print ifconfig
                print "###########################\n"
                print "mail to: <support [at] neurofuzzsecurity dot com>\n\n"
                sys.exit(1)

            # interfaces discovered, get a choice        
            try:
                var = raw_input("\nYour choice: ")
                
                # ensure choice is in range
                for f in thechoices:
                    if var == f[0]:
                        var = f
                        wecontinue = True
                        break
                
                if wecontinue:
                    self.setInterface(iface=var[0])
                    self.setOriginalMacAddress(mac=var[1])
                    self.persistData()
                    # check to see if DHCP is used
                    self.dhcpUsed = self.isDhcpUsed()
                else:
                    self.shutDown("Choice out of range")
            except ValueError, e:
                print e
                self.shutDown("Invalid input")
            except IndexError, e:
                print e
                self.shutDown("Invalid input")
        else:
            self.shutDown("Sorry but this is written to run on *nix platforms, grow up")
        
    def shutDown(self, s=""):
        """ output and program shutdown """
        print "\n%s, shutting down ...\n" % s
        sys.exit(0)
        
    def discoverPlatform(self):
        ''' calculates string identifying the running OS '''
        theos = platform.uname()[0].lower()
        un = platform.platform().lower()  
        if theos == "linux":
            if 'fedora' in un:
                return (theos, 'fedora')
            if 'debian' in un:
                return (theos, 'debian')
            if 'ubuntu' in un:
                return (theos, 'ubuntu')
        if theos == "darwin":
            return (theos, un)

    def isDhcpUsed(self):
        ''' tries to discover if DHCP is in use by the running host '''
        
        """
            this turned out to be a real pain in
            the ass !!! Every flavor of Linux does
            things differently enough that I had
            to make this quasi platform specific.
            I don't like it but it works until I
            can figure out a better way.
        """
        res = False
        dhcpterms = ['dhcp' ]
        thepattern = None
        # check to see if DHCP is enabled
        """
            on Linux - DHCP config data is saved
            into config files so we have to hunt
            those down and sift through them
        """
        if self.getRunningPlatform() == 'linux':
            """
                fedora uses ifcfg-interface files,
                such as:
                
                ifcfg-eth0
                
                so look for those if fedora is the
                detected OS
            """
            if self.getRunningPlatformFlavor() == 'fedora':
                thepattern = "ifcfg-" + self.targetInterface
                iface_file_handle = self.findFile(pattern=thepattern)[0]
            """
                deb and ubuntu seem to both use the file:
                
                /etc/network/interfaces
            """
            if self.getRunningPlatformFlavor() == 'debian' or \
                self.getRunningPlatformFlavor() == 'ubuntu':
                iface_file_handle = "/etc/network/interfaces"

            print "Found file ... %s, reading its contents" % iface_file_handle
            fcontent = self.readFile(fhandle=iface_file_handle)
            for d in dhcpterms:
                for fc in fcontent:
                    if d in fc:
                        res = True
        """
            on Mac - ipconfig getpacket en0
            any data back it means DHCP is used, otherwise
            there is no response
        """
        if self.getRunningPlatform() == 'darwin':
            poutput = self.runOsProcess(lParams=["ipconfig", "getpacket", self.targetInterface])
            if len(poutput) > 0:
                res = True

        return res
    
    def getDhcpUsed(self):
        return self.dhcpUsed
    
    def handleDhcpReset(self):
        ''' hanlde the DHCP client reset '''
        if self.dhcpUsed == True:
            # Linux
            if self.getRunningPlatform() == "linux":
                dhclient = self.which(program="dhclient")
                if dhclient:
                    print "On Linux ... running: %s" % dhclient
                    self.runOsProcess(lParams=[dhclient, "-r"])
                    time.sleep(5)
                    self.runOsProcess(lParams=[dhclient, self.targetInterface])
                else:
                    print "could not find an appropriate DHCP client, make sure your networking still works at this point"
            if self.getRunningPlatform() == "darwin":
                prog = "ipconfig"
                """
                    Mac OSX
                    sudo ipconfig set en0 BOOTP
                    sudo ipconfig set en0 DHCP
                """
                self.runOsProcess(lParams=[prog, "set", self.targetInterface, "BOOTP"])
                time.sleep(2)
                self.runOsProcess(lParams=[prog, "set", self.targetInterface, "DHCP"])
    

if __name__ == "__main__":
    # instantiate object
    spoofmac = MacCloak()
    
    if spoofmac.amIRoot() == True:
        print("========== Currently Available Interfaces ==========")
        print "===== Only displaying those with MAC Addresses ====="
    
        iface = spoofmac.getIface()
        
        print("====================================================")
        print "[*] The Current MAC address on interface '%s' is: '%s'" % (spoofmac.getInterface(),
                                                                          spoofmac.getOriginalMacAddress())
   
        print "DHCP usage detection: %s" % spoofmac.getDhcpUsed()
        # change MAC Address
        print "Changing MAC Address to something random"
        spoofmac.modMac(randomly=True)
    
        print("[*] Your New MAC address is: %s\n\n") % spoofmac.getFakeMacAddress()
        print "Now go do whatever it is you need to do with a spoofed MAC Address, wink wink\n\n"
        print "Press a key when you want to set the Mac back to normal"
        cr = raw_input("> ")
        """
            when using this in API form
            only make this call when your code is
            ready to set the interfaces MAC Address
            back to its original state
        """
        # change MAC Address back
        print "Changing MAC Address to its original value"
        spoofmac.modMac(randomly=False)
