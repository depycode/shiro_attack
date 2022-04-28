# -*- coding: utf-8 -*-
from Cryptodome.Cipher import AES
from Crypto import Random
from base64 import b64encode
from base64 import b64decode
from sys import argv

BS = AES.block_size
pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
unpad = lambda s: s[0:-s[-1]]
def encrypt(key, text):
    IV = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    data = b64encode(IV + cipher.encrypt(pad(text)))
    return data
def decrypt(key, enc):
    data = b64decode(enc)
    IV = data[0:16]
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    return unpad(cipher.decrypt(data[16:]))
    
    
if __name__ =='__main__':

    if len(argv)!=3:
        exit("use error, python decode.py key poc")
    else:
        k = argv[1]
        p = argv[2]
        key = b64decode(k)
        print(str(decrypt(key,p),encoding='utf-8',errors='ignore'))
