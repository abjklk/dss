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


#################################################################

# Function to read File
def readfile(a):
	f=open(a,"r")
	content=f.read().encode()
	f.close()
	return content

# Read input files.
msg1=readfile("1kb.txt")
msg2=readfile("1mb.txt")
msg3=readfile("2mb.txt")
msg4=readfile("5mb.txt")

#################################################################

def hashit(content):
	temp=SHA256.new(content).digest()
	return int.from_bytes(temp,byteorder='big' )

print("Hashing time")
with CodeTimer():
	digest1=hashit(msg1)
with CodeTimer():
	digest2=hashit(msg2)
with CodeTimer():
	digest3=hashit(msg3)
with CodeTimer():
	digest4=hashit(msg4)

#################################################################

# # Signature on direct message
# digest1=msg1.hex()
# digest2=msg2.hex()
# digest3=msg3.hex()
# digest4=msg4.hex()

#################################################################

# Generate key
print("\n\nKeygeneration Time")
with CodeTimer():
	bits=1024
	p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
	g=2
	s= randint(0, p-1)
	v = pow(g,s,p)
	e= Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
	e_1=(libnum.invmod(e, p-1))
	
#################################################################
# Sign the message
def sign(content):
	S_1=pow(g,e, p)
	S_2=((content-s*S_1)*e_1) % (p-1)
	return S_1,S_2

print("\n\nSigning time")
with CodeTimer():
	sig1,sig11=sign(digest1)
with CodeTimer():
	sig2,sig22=sign(digest2)
with CodeTimer():
	sig3,sig33=sign(digest3)
with CodeTimer():
	sig4,sig44=sign(digest4)
	
#################################################################
#Verify signature
def verify1(S_1,S_2,D):
	v_1 = (pow(v,S_1,p)*pow(S_1,S_2,p))%p
	v_2 = pow(g,D,p)
	return v_1==v_2

print("\n\n verification time")
with CodeTimer():
	verify1(sig1,sig11,digest1)
with CodeTimer():
	verify1(sig2,sig22,digest2)
with CodeTimer():
	verify1(sig3,sig33,digest3)
with CodeTimer():
	verify1(sig4,sig44,digest4)
