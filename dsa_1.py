#  General Imports
from Crypto.Hash import SHA256
import binascii
from linetimer import CodeTimer
#  Import specific to signature.
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

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
	return SHA256.new(content)

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
	key = DSA.generate(1024)
	publickey=key.publickey()	
#################################################################
# Sign the message
def sign(content,key):
	signer = DSS.new(key, 'fips-186-3')
	signature = signer.sign(content)
	return signature

print("\n\nSigning time")
with CodeTimer():
	sig1=sign(digest1,key)
with CodeTimer():
	sig2=sign(digest2,key)
with CodeTimer():
	sig3=sign(digest3,key)
with CodeTimer():
	sig4=sign(digest4,key)
	
#################################################################
#Verify signature
def verify1(signature,content):
	pkey=DSS.new(publickey,'fips-186-3')
	pkey.verify(content,signature)

print("\n\n verification time")
with CodeTimer():
	verify1(sig1,digest1)
with CodeTimer():
	verify1(sig2,digest2)
with CodeTimer():
	verify1(sig3,digest3)
with CodeTimer():
	verify1(sig4,digest4)
