"""
    Author: Andres Andreu
    Company: neuroFuzz, LLC
    Date: 10/10/2012
    Some functions ...

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
import random
import hashlib
from datetime import datetime, timedelta
from random import choice, randint, sample
from AntiIDS import AntiIDS

aids = AntiIDS()
def constructRequest(verb="", target="", resource="/"):
    """
        AntiIDS:
        
        mode 2 works ... / becomes /./
        mode 3 works ... / becomes /%20HTTP/1.1%0D%0A%0D%0AAccept%3A%20jl1HHDQ5wN/../../
        mode 4 works ... / becomes /Zw3w ... lots of randomness ... rZX/../
        mode 5 works ... / becomes /c2nHK1wXYP.html%3fXGpUu8y26l=/..//
    """
    ''' force more random choices towards the use of IDS evasion '''
    if len(verb) == 0:
        verb = choice(['HEAD', 'GET'])
    if getRandBool() == True:
        randpool = ['2','3','4','5']
        http_data = verb + " " + aids.encode_anti_ids(mode=choice(randpool),inuri=resource) + ' HTTP/1.1\n'
    else:
        http_data = verb + " " + resource + ' HTTP/1.1\n'
    # header line - all are optional but Host
    http_data = http_data + 'Host: ' + target + '\n'  # required
    http_data = http_data + 'Keep-Alive: 10\n'
    http_data = http_data + 'Accept: text/html\n'
    http_data = http_data + 'Connection: close\n'
    # separation line - required
    http_data = http_data + '\n'    # required
    
    return http_data

"""
    only include data we want to hash for baseline and baseline comparison
    data to include, first line (response code etc..)
    headers to include, server, content-type, location, content-length
"""
def stripheader(data,includeinbaseline):
    response = "" 
    for d in data.split('\r\n'):
        if d.startswith(tuple(includeinbaseline)):
            response += d
            #print d 
    return hashlib.sha1(response).hexdigest()

def getTermColor(color=""):
    cDict = {
             'red':'\033[31m',
             'green':'\033[32m',
             'reset':'\033[0;0m'
             }
    
    return cDict[color]

def outStatement(val="", result="Good", extra=None):
    if result == "Good":
        _color = getTermColor(color="green")
    if result == "Bad":
        _color = getTermColor(color="red")
    _reset = getTermColor(color="reset")
    
    if extra:
        #print "[*] %s%s%s -> %s --> %s" % (_color, val, _reset, result, extra)
        print "[*] %s%s%s --> %s" % (_color, val, _reset, extra)
    else:
        #print "[*] %s%s%s -> %s" % (_color, val, _reset, result)
        print "[*] %s%s%s" % (_color, val, _reset)
        
def createRandAlpha(length=0):
    return ''.join(choice(letters) for x in xrange(length or randint(10, 30)))

def getTimeStamp():

    FORMAT = '%Y.%m.%d.%H.%M.%S'
    return '%s' % datetime.now().strftime(FORMAT)

def sec_to_time(sec=0):
    sec = timedelta(seconds=sec)
    d = datetime(1,1,1) + sec

    print "\n\nDAYS\tHOURS\tMIN\tSEC"
    print "%d\t%d\t%d\t%d" % (d.day-1, d.hour, d.minute, d.second)
    print "\n"
    
def getRandBool():
    boolitems = { True: 80, False: 20 }
    return choice([k for k in boolitems for dummy in range(boolitems[k])])

def getRandReferer():
    ''' Returns a randomly chosen value to be used as the Referer '''
    ref = ['http://google.com','http://bing.com','http://www.yahoo.com']
    
    return sample(ref, 1)[0]

def getRandUserAgent():
    ''' Returns a randomly chosen value to be used as the User-Agent '''
    # pool of User-Agent headers to choose from
    headers = ['Googlebot/2.1 (http://www.googlebot.com/bot.html)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)',
               'Mozilla/4.0 (compatible; MSIE 6.0; MSN 2.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 4.0; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Win32)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; Arcor 5.005; .NET CLR 1.0.3705; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; YPC 3.0.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               "Mozilla/5.0 (compatible)",
               "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2) Gecko/20070219 Firefox/2.0.0.2",
               "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2)",
               "Mozilla/5.0 (compatible; Konqueror/2.2.2; Linux 2.4.14-xfs; X11; i686)",
               "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.29 Safari/525.13",
               "Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3",
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.8) Gecko/20050511',
               'Mozilla/5.0 (X11; U; Linux i686; cs-CZ; rv:1.7.12) Gecko/20050929',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; nl-NL; rv:1.7.5) Gecko/20041202 Firefox/1.0',
               'Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.7.8) Gecko/20050609 Firefox/1.0.4',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.9) Gecko/20050711 Firefox/1.0.5',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.10) Gecko/20050716 Firefox/1.0.6',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.7.12) Gecko/20050915 Firefox/1.0.7',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; nl; rv:1.8) Gecko/20051107 Firefox/1.5',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.3) Gecko/20060426 Firefox/1.5.0.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.8.0.4) Gecko/20060508 Firefox/1.5.0.4',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.6) Gecko/20060808 Fedora/1.5.0.6-2.fc5 Firefox/1.5.0.6 pango-text',
               'Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.0.7) Gecko/20060909 Firefox/1.5.0.7',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1) Gecko/20060601 Firefox/2.0 (Ubuntu-edgy)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070220 Firefox/2.0.0.2',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070221 SUSE/2.0.0.2-6.1 Firefox/2.0.0.2',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.9a1) Gecko/20061204 GranParadiso/3.0a1',
               "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
               "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8",
               "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7",
               "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
               "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
               "Windows-RSS-Platform/1.0 (MSIE 7.0; Windows NT 5.1)",
               "Windows NT 6.0 (MSIE 7.0)",
               "Windows NT 4.0 (MSIE 5.0)",             
               "Opera/6.x (Windows NT 4.0; U) [de]",
               "Opera/7.x (Windows NT 5.1; U) [en]",
               'Opera/8.0 (X11; Linux i686; U; cs)',
               'Opera/8.51 (Windows NT 5.1; U; en)',
               'Opera/9.0 (Windows NT 5.1; U; en)',
               'Opera/9.01 (X11; Linux i686; U; en)',
               'Opera/9.02 (Windows NT 5.1; U; en)',
               'Opera/9.10 (Windows NT 5.1; U; en)',
               "Opera/9.20 (Windows NT 6.0; U; en)",
               'Opera/9.23 (Windows NT 5.1; U; ru)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.50',
               'Mozilla/5.0 (Windows NT 5.1; U; en) Opera 8.50',
               "neuroFuzz testing (compatible)",
               "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)"
               ]
    return random.sample(headers, 1)[0]
