#  General Imports
from Crypto.Hash import SHA256
import binascii
from linetimer import CodeTimer
#  Import specific to signature.
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme

import socket	
import time		 


# Function to read File
def readfile(a):
	f=open(a,"r")
	content=f.read().encode()
	f.close()
	return content

# Read input files.
msg1=readfile("1kb.txt")

def hashit(content):
	return SHA256.new(content)

print("Hash time")
with CodeTimer():
	digest1=hashit(msg1)

# Key gen time
print("key gen time")
with CodeTimer():
	keyPair = RSA.generate(bits=1024)
	pubKey = keyPair.publickey()	

with open("rsakey.pem","w") as f:
	f.write(pubKey.export_key().decode())

# Sign the message
def sign(content,keyPair):
	signer = PKCS115_SigScheme(keyPair)
	signature = signer.sign(content)
	return signature

print("Sign time")
with CodeTimer():
	sig1=sign(digest1,keyPair)

print("===================")
print(msg1,sig1)
print(len(msg1))
print(len(sig1))
print("===================")

s = socket.socket()		 

port = 10001				

s.bind(('', port))
print("socket binded to",str(port))

s.listen(5)	 
print("socket is listening")


while True: 
	c, addr = s.accept()
	print('Got connection from', addr)
	c.send(msg1+sig1) 
	c.close()