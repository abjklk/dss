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

print("===========ECDSA Algorithm=============")
print("ECDSA Hash time")
with CodeTimer():
	digest1=hashit(msg1)

# Key gen time
print("ECDSA key gen time")
t0=time.time()
sk = SigningKey.generate(curve=SECP256k1)
vk = sk.verifying_key
t1=time.time()
keygentime=(t1-t0)*1000


with open("ecdsakey.pem","wb") as f:
	f.write(vk.to_string())

# Sign the message
def sign(content):
	signature = sk.sign(content)
	return signature

print("ECDSA Sign time")
t0=time.time()
sig1=sign(digest1)
t1=time.time()
signingtime=(t1-t0)*1000

with open("results.txt","a") as f:
	f.write("ECDSA keygen time " +str(keygentime)+ "ECDSA signing time " + str(signingtime)+"\n")


print("===================")
print(msg1,sig1)
print(len(msg1))
print(len(sig1))
print("===================")

s = socket.socket()		 

port = 10004			

s.bind(('', port))
print("socket binded to",str(port))

s.listen(5)	 
print("socket is listening")


while True: 
	c, addr = s.accept()
	print('Got connection from', addr)
	c.send(msg1+sig1) 
	c.close()
