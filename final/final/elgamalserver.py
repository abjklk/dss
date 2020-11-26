#  General Imports
from Crypto.Hash import SHA256
import binascii
from linetimer import CodeTimer
#  Import specific to signature.
from Crypto.Util.number import *
from Crypto import Random
import Crypto
import libnum
import sys
from random import randint
import hashlib

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
	temp=SHA256.new(content).digest()
	return int.from_bytes(temp,byteorder='big' )

print("Hash time")
with CodeTimer():
	digest1=hashit(msg1)

# Key gen time
print("key gen time")
t0=time.time()
bits=1024
p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
g=2
s= randint(0, p-1)
v = pow(g,s,p)
e= Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
e_1=(libnum.invmod(e, p-1))	
t1=time.time()
keygentime=(t1-t0)*1000

with open("elgamalkey.pem","w") as f:
	f.write(str(g)+"\n"+str(v)+"\n"+str(p)+"\n")


# Sign the message
def sign(content):
	S_1=pow(g,e, p)
	S_2=((content-s*S_1)*e_1) % (p-1)
	return S_1,S_2

print("Sign time")
t0=time.time()
sig1,sig11=sign(digest1)
t1=time.time()
signingtime=(t1-t0)*1000

sig1=str(sig1).zfill(310)
sig11=str(sig11).zfill(310)
sig1=sig1.encode()
sig11=sig11.encode()

print("===================")
print(msg1,sig1,sig11)
print(len(msg1))
print(len(sig1))
print(len(sig11))
print("===================")

with open("results.txt","a") as f:
	f.write("Elgamal keygen time " +str(keygentime)+"\n"+ "Elgamal signing time " + str(signingtime)+"\n")

s = socket.socket()		 

port = 10002			

s.bind(('', port))
print("socket binded to",str(port))

s.listen(5)	 
print("socket is listening")


while True: 
	c, addr = s.accept()
	print('Got connection from', addr)
	c.send(msg1+sig1+sig11) 
	c.close()