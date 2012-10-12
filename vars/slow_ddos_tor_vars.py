"""
    variables to be used by the slow_ddos_tor class
"""
# modifiable variables
########################################################
host = "host"
port = 80
threads = 100
sleepTime = 1000
uri = "/"
torip = "127.0.0.1"
sleepLowerBound = 5
sleepUpperBound = 30
choicePool = ''.join(map(chr, range(48, 58)) + map(chr, range(65, 91)) + map(chr, range(97, 123)))
hostheader = ""
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
