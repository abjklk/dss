#  General Imports
from Crypto.Hash import SHA256
import binascii
from linetimer import CodeTimer
#  Import specific to signature.
import ed25519

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
	return SHA256.new(content).digest()

print("Hash time")
with CodeTimer():
	digest1=hashit(msg1)

# Key gen time
print("key gen time")
with CodeTimer():
	privKey, pubKey = ed25519.create_keypair()

with open("eddsakey.pem","wb") as f:
	f.write(pubKey.to_bytes())

# Sign the message
def sign(content):
	signature = privKey.sign(content, encoding='hex')
	return signature

print("Sign time")
with CodeTimer():
	sig1=sign(digest1)

print("===================")
print(msg1,sig1)
print(len(msg1))
print(len(sig1))
print("===================")

s = socket.socket()		 

port = 10005				

s.bind(('', port))
print(f"socket binded to {port}")

s.listen(5)	 
print("socket is listening")


while True: 
	c, addr = s.accept()
	print('Got connection from', addr)
	c.send(msg1+sig1) 
	c.close()