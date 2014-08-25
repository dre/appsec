"""
    variables to be used by the web_traffic_tor class
"""
# modifiable variables
########################################################
host = "50.75.249.29"
port = 8000
threads = 100
sleepTime = 1000
uri = "/"
torip = "127.0.0.1"
sleepLowerBound = .2
sleepUpperBound = 1
choicePool = ''.join(map(chr, range(48, 58)) + map(chr, range(65, 91)) + map(chr, range(97, 123)))
hostheader = "z.bayshorenetworks.com"
########################################################

def getHost():
    return host

def getPort():
    return port

def getSleepTime():
    return sleepTime

def getUri():
    return uri

def getTorIp():
    return torip

def getThreads():
    return threads

def getHostHeader():
    if len(hostheader) > 0:
        return hostheader
    else:
        return None

def getSleepBounds():
    return(sleepLowerBound,sleepUpperBound)

def getChoicePool():
    return choicePool
