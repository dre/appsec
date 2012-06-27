"""
    Author:      Andres Andreu <andres [at] neurofuzz dot com>
    File:        cisco_VPN_group_password_decrypt.py
    Date:        5/21/2011
    Modified:    9/15/2011
    
    Today (5/21/2011) was supposed to be the end of the world ... 
    guess not :-)
    
    A Cisco VPN group password decryption python script.
    I wrote this because I used other tools to achieve
    the decryption result but I wanted to understand it
    myself.
    
    Dependency:
    pyDes - http://twhiteman.netfirms.com/des.html
    
    MIT-LICENSE
    Copyright (c) 2011 Andres Andreu, neuroFuzz LLC

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
    send me feedback if its any good.
"""
from pyDes import *
import hashlib
import re
import sys

#debug = True
debug = False
##################################################################
def HexToRawAscii(hString, retList=True):
    tmp = ""
    # if it has spaces convert to list
    if type(hString) != list:
        if " " in hString:
            hString = list(hString.split())
        else:
            hString = splitStringByTwo(hString)
            
    if type(hString) == list:
        # convert hex ciphertext to binary
        for s in hString:
            tmp += chr(int(s, 16))
    # return list or string
    if retList:
        return tmp.split()
    else:
        return tmp
# EOF: HexToAscii

def splitStringByTwo(s):
    hTmp = []
    if not " " in s:
        for i in range(len(s)/2):
            realIdx = i*2
            val = s[realIdx:realIdx+2]
            if isHexEncoded(val):
                hTmp.append(val)
    elif " " in s:
        hTmp = removeSpaceStr(s, retList=True)
    return hTmp
# EOF: splitStringByTwo

def isHexEncoded(s):
    if type(s) == list:
        s = ''.join(s)
    if " " in s:
        s = ''.join(s.split())
        
    if len(s) % 2 == 0:
        if re.match('[A-Fa-f0-9]', s):
            return True
    return False
# EOF: isHexEncoded

def removeSpaceStr(s, retList=False):
    if retList:
        return s.split()
    else:
        return ''.join(s.split())
# EOF: removeSpaceStr

def crack(thedata):
    ciphertext = HexToRawAscii(thedata, retList=False)
    if len(ciphertext) > 40:
        
        iv = ciphertext[0:8]
        ht = ciphertext[0:20]
        
        thechr = chr(ord(ht[19])+1)
        thechr1 = chr(ord(ht[19])+3)
        
        ht = ht[0:19]
        ht = ht+thechr
        h4 = ciphertext[20:40]
        
        m = hashlib.sha1()
        m.update(ht)
        h2 = m.digest()
        
        ht = ht[0:19]
        ht = ht+thechr1
        
        mm = hashlib.sha1()
        mm.update(ht)
        h3 = mm.digest()
        
        key = h2[0:20] + h3[0:4]
        ciphertextBytesWithoutHeader = ciphertext[40:len(ciphertext)]
        if debug:
            print "\nCiphertext: %s - %d" % (ciphertext,len(ciphertext))
            print "HT: %s - %d" % (ht,len(ht))
            print "H4: %s - %d" % (h4,len(h4))
            print "H2: %s - %d" % (h2,len(h2))
            print "HT: %s - %d" % (ht,len(ht))
            print "H3: %s - %d" % (h3,len(h3))
            print "ciphertext to crack: %s - %d" % (ciphertextBytesWithoutHeader,len(ciphertextBytesWithoutHeader))
            print "Key: %s - %d" % (key,len(key))
            print "Iv: %s - %d\n" % (iv,len(iv))
        
        k = triple_des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        return k.decrypt(ciphertextBytesWithoutHeader)
    else:
        return None
# EOF: crack

def doInvalidOutput(s):
    print "\nHash '%s' is not a valid Cisco VPN group password hash\n" % s
# EOF: doInvalidOutput

def doValidOutput(x,y):
    print "\nCracked: \nCiphertext: %s\nCleartext: %s\n" % (x,y)
# EOF: doValidOutput
##################################################################
"""
    These are some samples of the value my python code is expecting. 
    It comes from the cisco VPN .PCF file. This is the encrypted data 
    saved in that file as the value for the key 'enc_GroupPwd'.
    grabbed a couple of them from: 
    http://jmatrix.net/dao/case/case.jsp?case=7F000001-933BCB-10901BBA2D1-C1E
"""
ciphertextArr = ["A46CCC062614AADAFD18C3B579317B2657C78AD686EE123B02BB99AD3FCB64E6F6E3398F4D684FBA76E75D9AFAB09EC0DA069BD77F7240F3506EAEC2186E05A3",
                 "8D294660D70121E4D414D1F5E1F4D47C6B25915B4E63E5235A19733EEF46DF7C50557BBBA74A7B667C254AB32A70418782792A4BED422963",
                 "CA2A193302283B48BC3EA0A508E4E41E9B2A40A5B4BAC61877C147D3A00C6FD91806FC1F675F76BC8A60EFFD464D70873A97A07019F34E0F6F1EBAFD910E5D53",
                 "BB4C6368F9A6AAD112A21DF982432E7AC147A8521998EE949416DD40160470BF0AE697D92A156844305D920107C4429BECC37158F9F83F5CC090457707AD12983E6313CB2AC274545460AA5905FAF73D",
                 "9ECB9B535F2E7EEAFEC1779AFDB0A21F8648EA2A09A41F458CF261590688D756DCA002E21D0D3210A45A645B4587D2A8",
                 "EAD7CD8CE0C8E565CF316506F806D2FB26C878DF535B687CB21FAA15818750292B260A414F00E3912151C9028AFA2314094B0F9137311239",
                 "CD274445B0BFF52C9E84B0A45A2FBEF168A1B9E3A291971CA85AC41CBD4971D40DA0A9D38CF1883929E1212C5C927123",
                 "E78AD0411F9FA907332A23253103098C5F4DBA373B08D3DD5AE3B15E43BE109236204D1A5262DD4E71E40C6F6F7BC13E3629809BA05EF3D5AD9008BBFA1D2620",
                 "80F4247E78DAF553AC52E2B33561C39047891FEDF2D93037D12F61CB400E114E616680D23D6156077FC54C5BD1689CAD74EC9E34AC7C87F49DF2C5DAF274F1674BA0EBED911751C1",
                 "CCD84ED9BBEC0326AA6626996C9F12AA59748D036478E43FB9E83464C75B5C56A7EF0091A958878541A944449504DD9C7C95DF8103D905A031B9BF6AA85EFAACA2C2A29D5E48D7C5B451D30374E40645",
                 "CCD84ED9BBEC0326AA6626996C9F12AA59748D036478E43FB9E83464C75B5C56A7EF0091A958878541A944449504DD9C7C95DF8103D905A031B9BF6AA85EFAACA2C2A29D5E48D7C5B451D30374E4064",
                 "CCD84ED9BBEC0326AA6626996C9F12AA59748D036478E43FB9E83464C75B5C56A7EF0091A958878541A944449504DD9C7C95DF8103D905A031B9BF6AA85EFAACA2C2A29D5E48D7C5B451D30374E406",
                 "11E6093DCB609D2164F64C908A8965E77268EA694EFB9B8F4287882B993B2AF4D50D43417682B0581710DF825A4BF5396655497A95337B58",
                 "F52E48FF7B2C0835ED789479F87372269F31D7FBD4608FC9AA11DE10F6EA21D7647D62E30331AEC49F5E8C08AF60C7D76AF56014681C0DDF",
                 "67A4444108D52A678BB709C1E06269A2520C9960E1B83F0429C2EE731669DFFDA966E24BB8026962D743105B37F59CD5"
                 ]

# main prog
if len(sys.argv) > 1:
    try:
        ciphertext = sys.argv[1]
        cracked = crack(ciphertext)
        if cracked:
            doValidOutput(ciphertext,cracked)
        else:
            doInvalidOutput(ciphertext)
    except:
        doInvalidOutput(sys.argv[1])
else:
    print
    for ciphertext in ciphertextArr:
        try:
            cracked = crack(ciphertext)
            if cracked:
                doValidOutput(ciphertext,cracked)
            else:
                doInvalidOutput(ciphertext)
        except ValueError:
            doInvalidOutput(ciphertext)
    print
