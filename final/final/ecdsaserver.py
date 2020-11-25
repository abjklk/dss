#  General Imports
from Crypto.Hash import SHA256
import binascii
from linetimer import CodeTimer
#  Import specific to signature.
from ecdsa import SigningKey, SECP256k1

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
	sk = SigningKey.generate(curve=SECP256k1)
	vk = sk.verifying_key


with open("ecdsakey.pem","wb") as f:
	f.write(vk.to_string())

# Sign the message
def sign(content):
	signature = sk.sign(content)
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

port = 10004			

s.bind(('', port))
print(f"socket binded to {port}")

s.listen(5)	 
print("socket is listening")


while True: 
	c, addr = s.accept()
	print('Got connection from', addr)
	c.send(msg1+sig1) 
	c.close()