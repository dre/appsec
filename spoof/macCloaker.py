"""
    Author:     Andres Andreu
    Contact:    <andres [at] neurofuzz dot com>
    Company:    neuroFuzz, LLC
    Date:       6/23/2012
    Modified:   6/26/2012
    
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
    
    It stores a record of your MAC Address activity with
    this tool in a file called: .originalMac
    the data in there is structured as such:
    
        interface tab MAC_Address tab #pid#date/time_stamp
    
    where the pid is that of the prog run when that change
    was made. An example:
    
        eth0    07:c8:6f:23:32:f0    #764#2012-06-25T23:49:15.405275
        
    *** CAVEAT: currently some wireless adaptors do not enjoy this
    process and this process may fail. I will fix that when I have
    some time. Or maybe someone else steps up and does this. ***
    
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
    condition or flavor of Linux under the Sun.
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
        if len(mac) == 17:
            self.originalMacAddress = mac
        if len(mac) == 16:
            self.originalMacAddress = '0' + mac
        
    def getInterface(self):
        return self.targetInterface
        
    def getOriginalMacAddress(self):
        return self.originalMacAddress

    def setFakeMacAddress(self, val=""):
        if len(val) == 17:
            self.fakeMacAddress = val
        if len(val) == 16:
            self.fakeMacAddress = '0' + val
        
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
        
        """
            sometimes we run into this error, especially
            on Ubuntu hosts for some strange reason:
            
                SIOCSIFHWADDR: Cannot assign requested address

            probably indicates that the requested MAC address 
            is not a unicast address. To qualify as a unicast
            address the first byte must be even. A crazy regex
            to check for this is:
            
            ^[a-fA-F0-9][aceACE02468][:|\-]?([a-fA-F0-9]{2}[:|\-]?){4}[a-fA-F0-9]{2}$
            
            so my original function has to be modified ...

        mac = [random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff)]
        return (':'.join(map(lambda x: "%02x" % x, mac)))
        """
        firstByte = "0x0" + random.choice('aceACE02468')
        mac = [ #0x00,
               int(firstByte, 16),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

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
            state, use ifconfig
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
        if thestate == "down":
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, thestate])
        if thestate == "up":
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, thestate])
    
    def readFile(self, fhandle=""):
        try:
            f = open(fhandle, 'r')
            fcontent = f.readlines()
            f.close()
            return fcontent
        except Exception, e:
            print e
 
    def useMacchanger(self):
        ''' use macchanger to take action on the interface '''
        
        print("Changing your original MAC address (%s) to something totally random...\n" % self.getOriginalMacAddress())
        macchanger = self.which(program="macchanger")
        
        # Puts interface down
        self.modInterfaceState(thestate='down')
        if self.checkIfaceStateDown() == 1:

            # change the MAC Address
            poutput = self.runOsProcess(lParams=[macchanger, "--random", self.targetInterface])
        
            self.setFakeMacAddress(val=poutput[poutput.index("Faked")+2])

            # Puts interface up
            self.modInterfaceState(thestate='up')
            if self.checkIfaceMacAddress(fake=True) == 1:
                if self.checkIfaceStateUp() == 1:
                    self.handleDhcpReset()
                    
    def useIfconfig(self, randomly=False):
        ''' use ifconfig to take action on the interface '''
        """
            either randomly or back to normal
        """
        if randomly == True:
            randVal = self.randomMAC()
            self.setFakeMacAddress(val=randVal)
            print("Changing your original MAC address (%s) to something totally random...\n" % self.getOriginalMacAddress())
            
            # on Linux - ifconfig en1 hw ether 00:e2:e3:e4:e5:e6
            if self.getRunningPlatform() == "linux":
                if self.processLinux(randVal=randVal) == False:
                    self.failedExit()
            # on Mac OSX - ifconfig en1 ether 00:e2:e3:e4:e5:e6
            if self.getRunningPlatform() == "darwin":
                if self.processDarwin(randVal=randVal) == False:
                    self.failedExit()
        else:
            """
                this section sets the MAC Address back
                to its normal and original setting
            """
            print("Changing your MAC address to its original value ... %s") % self.originalMacAddress
            # on Linux
            if self.getRunningPlatform() == "linux":
                if self.processLinux() == False:
                    self.failedExit()
            # on Mac OSX 
            if self.getRunningPlatform() == "darwin":
                if self.processDarwin() == False:
                    self.failedExit()
                    
    def failedExit(self):
        print "Process failed, exiting"
        sys.exit(1)
                
    def checkIfaceStateUp(self):
        targ = 15
        cnt = 0
        while True:
            procOut = self.runOsProcess(lParams=[self.defaultProg])
            if self.targetInterface in procOut:
                print "Interface is up"
                return 1
            if cnt == targ:
                print "Interface seems up"
                return 1
            cnt += 1
            
    def checkIfaceStateDown(self):
        targ = 15
        cnt = 0
        while True:
            procOut = self.runOsProcess(lParams=[self.defaultProg])
            if self.targetInterface in procOut:
                print "Interface is up"
                return 0
            if cnt == targ:
                print "Interface seems down"
                return 1
            cnt += 1
    
    def checkIfaceMacAddress(self, fake=True):
        time.sleep(5)
        targ = 5
        cnt = 0
        ret = 0
        while True:
            procOut = self.runOsProcess(lParams=[self.defaultProg])
            if fake == True:
                if self.fakeMacAddress in procOut:
                    print "MAC Address %s SET" % self.fakeMacAddress
                    ret = 1
                    break
            else:
                if self.originalMacAddress in procOut:
                    print "MAC Address %s SET" % self.originalMacAddress
                    ret = 1
                    break
            if cnt == targ:
                ret = 0
                break
            cnt += 1
        return ret
            
    def processLinux(self, randVal=None):
        ''' set MAC Address to some altered state on Linux'''
        # Puts interface down
        self.modInterfaceState(thestate='down')
        """
            look for confirmation of interface
            being in a down state
        """
        if self.checkIfaceStateDown() == 1:
            # alter MAC Address
            if randVal != None:
                self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, 
                                           "hw", "ether", randVal])
            else:
                self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, 
                                           "hw", "ether", self.originalMacAddress])
            """
                look for confirmation of the new
                MAC Address being set in place
            """
            # Puts interface up
            self.modInterfaceState(thestate='up')
            if randVal != None:
                if self.checkIfaceMacAddress(fake=True) == 1:
                    if self.checkIfaceStateUp() == 1:
                        self.handleDhcpReset()
                    return True
                else:
                    print "This shit didnt work"
                    if self.checkIfaceStateUp() == 1:
                        self.handleDhcpReset()
                    return False
            else:
                if self.checkIfaceMacAddress(fake=False) == 1:
                    if self.checkIfaceStateUp() == 1:
                        self.handleDhcpReset()
                    return True
                else:
                    print "This shit didnt work"
                    if self.checkIfaceStateUp() == 1:
                        self.handleDhcpReset()
                    return False

    def processDarwin(self, randVal=None):
        ''' set MAC Address to some altered state on Mac OSX '''
        # change the MAC Address
        if randVal != None:
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, 
                                       "ether", randVal])
        else:
            self.runOsProcess(lParams=[self.defaultProg, self.targetInterface, 
                                       "ether", self.originalMacAddress])
        time.sleep(2)
        # Puts interface down
        self.modInterfaceState(thestate='down')
        # Puts interface up
        if self.checkIfaceStateDown() == 1:
            self.modInterfaceState(thestate='up')
            if randVal != None:
                if self.checkIfaceMacAddress(fake=True) == 1:
                    if self.checkIfaceStateUp() == 1:
                        self.handleDhcpReset()
                    return True
                else:
                    print "This shit didnt work"
                    if self.checkIfaceStateUp() == 1:
                        self.handleDhcpReset()
                    return False
            else:
                if self.checkIfaceMacAddress(fake=False) == 1:
                    if self.checkIfaceStateUp() == 1:
                        self.handleDhcpReset()
                    return True
                else:
                    print "This shit didnt work"
                    if self.checkIfaceStateUp() == 1:
                        self.handleDhcpReset()
                    return False
            
        
        """
        if self.modInterfaceState(thestate='up'):
            print("Interface is %s" % 'up')
        time.sleep(10)
        self.handleDhcpReset()
        """
        
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
                
                this MAC regex: ([0-9a-fA-F]{2}:?){6} seemed good
                but gave way too many false positives on Linux
            """
            if self.getRunningPlatform() == 'linux':
                thechoices = re.findall(r'^([\w]*):? [\w=<,>:.\s]*(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', ifconfig, re.MULTILINE)
                #thechoices = re.findall(r'^([\w]*):? [\w=<,>:.\s]*(([0-9a-fA-F]{2}:?){6})', ifconfig, re.MULTILINE)    
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
        ''' handle the DHCP client reset '''
        """
            if dhcp is used then restart client ...
            if we only bring up the interface and
            dont renew dhclient lease then full
            network connectivity is not restored
            
            I am leaving the Linux DHCP restart
            outside of the conditional check on
            var dhcpUsed. The reason for this is
            that I had trouble deciphering DHCP
            use on some flavors of Linux. DHCP
            restarts on non-DHCP using interfaces
            don't seem to have an adverse effect.
            This is not clean but works for now. 
        """
        if self.getRunningPlatform() == "linux":
            dhclient = self.which(program="dhclient")
            if dhclient:
                print "On Linux ... running: %s" % dhclient
                self.runOsProcess(lParams=[dhclient, "-r"])
                time.sleep(5)
                self.runOsProcess(lParams=[dhclient, self.targetInterface])
            else:
                print "could not find an appropriate DHCP client,"
                print "make sure your networking still works at this point\n"

        
        if self.dhcpUsed == True:
            # Linux
            """
            if self.getRunningPlatform() == "linux":
                dhclient = self.which(program="dhclient")
                if dhclient:
                    print "On Linux ... running: %s" % dhclient
                    self.runOsProcess(lParams=[dhclient, "-r"])
                    time.sleep(5)
                    self.runOsProcess(lParams=[dhclient, self.targetInterface])
                else:
                    print "could not find an appropriate DHCP client,"
                    print "make sure your networking still works at this point"
            """
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
        print "The Current MAC address on interface '%s' is: '%s'" % (spoofmac.getInterface(),
                                                                      spoofmac.getOriginalMacAddress())
   
        print "DHCP usage detection: %s" % spoofmac.getDhcpUsed()
        # change MAC Address
        print "Changing MAC Address to something random"
        spoofmac.modMac(randomly=True)
    
        print("Your New MAC address is: %s\n\n") % spoofmac.getFakeMacAddress()
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
        spoofmac.modMac(randomly=False)
