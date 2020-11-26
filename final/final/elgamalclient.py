import socket			 
from linetimer import CodeTimer
from Crypto.Hash import SHA256
from Crypto.Util.number import *
from Crypto import Random
import Crypto
import libnum
import sys
from random import randint
import hashlib
import time

s = socket.socket()		 

port = 10002				

s.connect(('localhost', port)) 

x = s.recv(1664)
msg1 = x[:1044]
sig1 = x[1044:1354].decode()
sig11 = x[1354:].decode()

sig1=int(sig1)
sig11=int(sig11)

print(msg1.decode())
print(sig1)

#Verify signature
with open("elgamalkey.pem") as f:
	g=int(f.readline())
	v=int(f.readline())
	p=int(f.readline())

def verify1(S_1,S_2,D):
	v_1 = (pow(v,S_1,p)*pow(S_1,S_2,p))%p
	v_2 = pow(g,D,p)
	return v_1==v_2

def hashit(content):
	temp=SHA256.new(content).digest()
	return int.from_bytes(temp,byteorder='big' )

print("Hashing time")
t0=time.time()
digest1=hashit(msg1)
t1=time.time()
hashingtime=(t1-t0)*1000

print("\n\n verification time")
t0=time.time()
verify1(sig1,sig11,digest1)
t1=time.time()
verificationtime=(t1-t0)*1000

with open("results.txt","a") as f:
	f.write("Elgamal Hashing time " +str(hashingtime)+"\n"+ "Elgamal verification time " + str(verificationtime)+"\n")

s.close()	 
