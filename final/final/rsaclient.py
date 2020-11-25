import socket			 
from linetimer import CodeTimer
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme

s = socket.socket()		 

port = 10001			

s.connect(('10.10.10.1', port)) 

x = s.recv(1172)
msg1 = x[:1044]
sig1 = x[1044:]
print(msg1.decode())
print(sig1)

#Verify signature
with open("rsakey.pem") as f:
	pubKey = RSA.import_key(f.read())

def verify1(content,signature,pubKey):
	verifier = PKCS115_SigScheme(pubKey)
	verifier.verify(content,signature)

def hashit(content):
	return SHA256.new(content)

print("Hashing time")
with CodeTimer():
	digest1=hashit(msg1)

print("\n\n verification time")
with CodeTimer():
	verify1(digest1,sig1,pubKey)

s.close()	 
