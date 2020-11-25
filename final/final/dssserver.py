#  General Imports
from Crypto.Hash import SHA256
import binascii
from linetimer import CodeTimer
#  Import specific to signature.
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

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
	key = DSA.generate(1024)
	publickey=key.publickey()	

with open("dsskey.pem","w") as f:
	f.write(publickey.export_key().decode())

# Sign the message
def sign(content,key):
	signer = DSS.new(key, 'fips-186-3')
	signature = signer.sign(content)
	return signature

print("Sign time")
with CodeTimer():
	sig1=sign(digest1,key)

print("===================")
print(msg1,sig1)
print(len(msg1))
print(len(sig1))
print("===================")

s = socket.socket()		 

port = 10003				

s.bind(('', port))
print(f"socket binded to {port}")

s.listen(5)	 
print("socket is listening")


while True: 
	c, addr = s.accept()
	print('Got connection from', addr)
	c.send(msg1+sig1) 
	c.close()