#  General Imports
from Crypto.Hash import SHA256
import binascii
from linetimer import CodeTimer
#  Import specific to signature.
import ed25519

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
	return SHA256.new(content).digest()

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
	privKey, pubKey = ed25519.create_keypair()
	
#################################################################
# Sign the message
def sign(content):
	signature = privKey.sign(content, encoding='hex')
	return signature


print("\n\nSigning time")
with CodeTimer():
	sig1=sign(digest1)
with CodeTimer():
	sig2=sign(digest2)
with CodeTimer():
	sig3=sign(digest3)
with CodeTimer():
	sig4=sign(digest4)
	
#################################################################
#Verify signature
def verify1(content,signature):
	 pubKey.verify(signature, content, encoding='hex')

print("\n\n verification time")
with CodeTimer():
	verify1(digest1,sig1)
with CodeTimer():
	verify1(digest2,sig2)
with CodeTimer():
	verify1(digest3,sig3)
with CodeTimer():
	verify1(digest4,sig4)
