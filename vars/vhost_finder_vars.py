"""
    variables to be used by the VHostFinder class
"""
# modifiable variables
########################################################
target_ip = "127.0.0.1"
target_port = 8080
target_domain = "domain"
target_tld = "com"
useslowdos = True
anonimize = True
vhost_finder_threads = 20
vhost_finder_debug = False
displayThreshold = 500
depthLowerBound = 1
depthUpperBound = 2
########################################################

def getTargetIp():
    return target_ip

def getTargetPort():
    return target_port

def getTargetDomain():
    return target_domain

def getTargetTld():
    return target_tld

def getUseSlowDoS():
    return useslowdos

def getVHostNumThreads():
    return vhost_finder_threads

def getVHostDebug():
    return vhost_finder_debug

def getAnonimize():
    return anonimize

def getDisplayThreshold():
    return displayThreshold

def getDepthBounds():
    return(depthLowerBound,depthUpperBound)
