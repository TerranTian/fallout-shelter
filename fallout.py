#! /usr/bin/env python
#coding=utf-8
import os
import sys
import base64
import json

from pbkdf2 import PBKDF2
from Crypto.Cipher import AES


main_key = b'tu89geji340t89u2'
pwd = (base64.b64encode('PlayerData'.encode('utf-8')))[:8]
key = PBKDF2(pwd, main_key).read(32)


def readString(path):
    if(not os.path.exists(path)):
        return "";
    f = open(path,"r");
    r = f.read();
    f.close();
    return r;

def writeString(path,content):
    f = open(path,"w");
    f.write(content);
    f.close();

def encrypt(data):
    aes = AES.new(key, AES.MODE_CBC, main_key)
    result = data.encode('utf-8')
    if len(result) % 16 != 0:
        result += (16 - (len(result) % 16)) * b'\t'
    result = aes.encrypt(result)
    result = base64.b64encode(result)
    
    return result

def decrypt(data):
    key = PBKDF2(pwd, main_key).read(32)
    aes = AES.new(key, AES.MODE_CBC, main_key)
    data = base64.b64decode(data)
    return aes.decrypt(data);

if __name__ == '__main__':
	if(len(sys.argv)<2):
		sys.exit(1);
	cmd = sys.argv[1]
	path = sys.argv[2]

	outname = path.split(".")[0]

	if(cmd == "d"):
		data = readString(path);
		result = decrypt(data);
		writeString(outname+".json",result);
		print "decrypt done: "+outname+".json";
	else:
		data = readString(path);
		result = encrypt(data);
		writeString(outname+".sav",result);
		print "encrypt done: "+outname+".sav";


