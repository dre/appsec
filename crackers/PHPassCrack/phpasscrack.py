"""
    Author: Andres Andreu <andres [at] neurofuzz dot com>
    Company: neuroFuzz, LLC
    Date: 8/1/2010
    Prototype prog written to do dictionary/brute force cracking
    against a given phpass hash

    Copyright (C) 2010 Andres Andreu

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    #######################################################################
    phpass is an implementation of the password hashing
    mechanism used in PHP by wordpress version 2.5 and
    above as well as many other current PHP based
    project that requires storage of user passwords.

    this is a simple multi threaded dictionary based
    brute force prototype of a prog to crack password
    hashes extracted from a wordpress MySQL DB. while
    other PHP based progs use phpass this task came
    my way due to an exposed wordpress MySQL DB.
    the prog does not do the extraction, it currently
    expects the hashes in a file.

    in wordpress these hashes are usually stored in
    table 'wp_users'. the threading part is basically
    one thread per hash we are trying to crack

    Uses this lib written by Alexander Chemeris <Alexander.Chemeris@nospam@gmail.com>:
    phpass - http://www.openwall.com/phpass/contrib/phpass-python-0.1.tar.gz
    #######################################################################
"""
# libs
import phpass
import sys
import time
import stopwatch
import getopt
from threading import Thread
from threading import Event

##################################################################################################
# vars
progname = sys.argv[0]
fin = []
verbose = False
hashfile = ''
dictfile = ''
resultsfile = ''
max = 10
timer = stopwatch.StopWatch()
##################################################################################################
# input switches
"""
    -h,-d,-t must be followed by an argument, -v is optional
    So you tell getopt this by putting a colon after the switch in that
    parameter to the getopt function.
    sys.argv[1:] skips the name of our prog which is sys.argv[0],
    so start at index one
"""
try:
    opts, args = getopt.getopt(sys.argv[1:], "h:d:t:u:va")
except getopt.GetoptError:
    usage()
# populate the appropriate vars
for opt, arg in opts:
    if opt in ("-h"):
        hashfile = arg
    if opt in ("-d"):
        dictfile = arg
    if opt in ("-t"):
        resultsfile = arg
    if opt in ("-v"):
        verbose = True
##################################################################################################
# class
class PHPassHashCracker(Thread):
    def __init__(self, threadID, dic, hash, nap_time):
        Thread.__init__(self)
        self.dic = dic
        self.cracked = 0
        self.thash = hash
        self.threadID = threadID
        self.nap_time = nap_time
        self.times_run = 0
        self.exit_event = Event()
        self.start()

    def exit(self,wait_for_exit=False):
        if verbose:
            print '        [-] Thread asked to exit, messaging run'
        self.exit_event.set()
        if wait_for_exit:
            if verbose:
                print '        [-] Standby, thread exit waiting for run to finish'
            self.join()
        return self.report()

    def run(self):
        if verbose:
            print '    [!] Running thread: %s' % self.threadID
        while not self.exit_event.isSet():
            self.times_run += 1
            try:
                for word in self.dic:
                    # matching hash to word
                    if phpass.crypt_private(word, self.thash) == self.thash:
                        fin.append(word + " : " + self.thash)
                        self.cracked += 1
                    else:
                        continue
            except KeyboardInterrupt:
                print '\n [*] Aborted: exiting'
                sys.exit(1)

    def report(self):
        if self.is_alive():
            return "alive"
        else:
            if self.times_run > 1:
                stat = 'times'
            else:
                stat = 'time'
            return "Status:  I'm dead after running %d %s" % (self.times_run, stat)
# EOC
##################################################################################################
# funcs
def about():
    usage = '''

    Usage: %s -h hashes_file -d dictionary_file -t cracked_file

    Example: %s -h hashes -d dict -t cracked.txt

    Use -v if you want to see thread and hash related verbose info,
    but be warned that it can be a lot depending on the data you use.

    an example of verbose of output:

        [+] Loaded hash: $P$BGEAd9eq2tn473tc.EWQwqd4D/Ss91.
        [!] Running thread: wph1
            [-] Thread asked to exit, messaging run
            [-] Standby, thread exit waiting for run to finish
        [!] Thread wph1 - Status:  I'm dead after running 1 time\n''' % (progname, progname)

    return usage
# EOF

def main(hashfile, filetoappendto, dic):
    # open results file
    try:
        fappend = open(filetoappendto, 'a')
    except IOError:
        print '\n [-] Error opening %s to append to' % (filetoappend)
        sys.exit()
    # open hash file
    try:
        ofile = open(hashfile).readlines()
        print '\n [+] Loaded %d hashes' % (len(ofile))
    except IOError:
        print '\n [-] Error opening %s to read from' % (hashfile)
        sys.exit(1)

    # storing phpass hashes to crack here in hashes array
    hashes = [i.strip() for i in ofile]

    print '\n [*] Checking for hashes to crack ...'
    print '\n [*] Starting to crack at [%s] ...' % (time.ctime())
    timer.start()
    """
        Note:
        the wordpress hashes encountered while writing this
        were all 34 in length, this is based on wordpress
        versions 2.5 and above
    """
    cnt = 1
    for hash in hashes:
        if len(hash) == 34:
            if verbose:
                print '\n    [+] Loaded hash: %s' % (hash)

            # dynamic variable name for the WPH objects
            varname = 'wph'+str(cnt)
            # increment for the next iteration
            cnt += 1

            vars()[varname] = PHPassHashCracker(varname,dic,hash,1)
            # check whether or not the threads are alive
            if vars()[varname]:
                while vars()[varname].report() == 'alive':
                    if len(fin) > 0:
                        vars()[varname].exit(True)
                        if verbose:
                            print "    [!] Thread %s - %s" % (vars()[varname].threadID,vars()[varname].report())
                    continue
            time.sleep(2)
        else:
            print "Invalid hash: %s of length: %d" % (hash, len(hash))

    if len(fin) > 0:
        print '\n [+] +++++++++++++++++++++++++++++++++++++++++++++++++++'
        print ' [+] Any discovered hashes will print to screen below this.'
        print ' [+] They will also be placed in file \'%s\'.\n' % filetoappendto

        for ff in fin:
            datum = ff.split(" : ")
            toappend = '%s : %s\n' % (datum[0], datum[1])
            # writing successful match to file
            fappend.write(toappend)
            print " [!!] Password: '%s' was a hit against hash: '%s'" % (datum[0], datum[1])

        # give the threads 3 seconds to catch up
        time.sleep(3)
        print '\n [+] +++++++++++++++++++++++++++++++++++++++++++++++++++'

    timer.stop()
    print "\n [-] Threads are cleaning up, please hold for about 5 seconds ..."
    for i in range(1,6):
        print "    [*] %d ..." % i
        time.sleep(1)

    fappend.close()
    print '\n [+] Cracked %d out of %d hashes on [%s]\n' % (len(fin), len(hashes), time.ctime())
    print " [!] Actual prog crack runtime: %s" % timer.elapsed()
# EOF
##################################################################################################
# start prog
if __name__=='__main__':
    # make sure we have all 3
    if not hashfile or not dictfile or not resultsfile:
        print about()
        sys.exit(1)

    # opening dictionary file
    try:
        ofile = open(dictfile).readlines()
    except IOError:
        print '\n [-] Error opening %s to read from' % (dictfile)
        sys.exit(1)

    # storing dictionary words in array dic
    dic = [i.strip() for i in ofile]

    print '\n [+] Loaded %d words from dictionary file' % (len(dic))
    main(hashfile, resultsfile, dic)
