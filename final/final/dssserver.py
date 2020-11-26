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
print("=============DSS Algorithm=============")
print("DSS Hash time")
with CodeTimer():
	digest1=hashit(msg1)

# Key gen time
print("DSS key gen time")
t0=time.time()
key = DSA.generate(1024)
publickey=key.publickey()	
t1=time.time()
keygentime=(t1-t0)*1000

with open("dsskey.pem","w") as f:
	f.write(publickey.export_key().decode())

# Sign the message
def sign(content,key):
	signer = DSS.new(key, 'fips-186-3')
	signature = signer.sign(content)
	return signature

print("DSS Sign time")
t0=time.time()
sig1=sign(digest1,key)
t1=time.time()
signingtime=(t1-t0)*1000

print("===================")
print(msg1,sig1)
print(len(msg1))
print(len(sig1))
print("===================")

s = socket.socket()		 

port = 10003				

s.bind(('', port))
print("socket binded to",str(port))

s.listen(5)	 
print("socket is listening")

with open("results.txt","a") as f:
	f.write("DSS keygen time " +str(keygentime)+ "DSS signing time " + str(signingtime)+"\n")

while True: 
	c, addr = s.accept()
	print('Got connection from', addr)
	c.send(msg1+sig1) 
	c.close()
