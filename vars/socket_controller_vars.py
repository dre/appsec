"""
    variables to be used by the SocketController class
"""
# modifiable variables
########################################################
torpath = "/Applications/Vidalia.app/Contents/MacOS/tor"
base_socks_port = 9052
base_control_port = 8120
socketLowerBound = 1
socketUpperBound = 5
datadir = '/Users/andresandreu/software_engineering/appsec/recon/vhost_finder/tordata'
debug = False
selfip = '127.0.0.1'
torfname = 'tor%sfile'
torarguments = {"--RunAsDaemon":'1',
                "--CookieAuthentication":'0',
                "--HashedControlPassword":'',
                "--ControlPort":'%s',
                "--PidFile":'tor%s.pid',
                "--SocksPort":'%s',
                "--DataDirectory":datadir + '/tor%s'
                }
########################################################

def getTorPath():
    return torpath

def getBaseSocksPort():
    return base_socks_port

def getBaseControlPort():
    return base_control_port

def getDataDir():
    return datadir

def getDebug():
    return debug

def getSocketIp():
    return selfip

def getTorFileName():
    return torfname

def getTorArguments():
    return torarguments

def getSocketBounds():
    return(socketLowerBound,socketUpperBound)

