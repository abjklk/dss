import socket			 
from linetimer import CodeTimer
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import DSA

s = socket.socket()		 

port = 12345				

s.connect(('localhost', port)) 

x = s.recv(1084)
msg1 = x[:1044]
sig1 = x[1044:]
print(msg1.decode())
print(sig1)

#Verify signature
with open("publickey.pem") as f:
	publickey = DSA.import_key(f.read())

def verify1(signature,content):	
	pkey=DSS.new(publickey,'fips-186-3')
	pkey.verify(content,signature)

def hashit(content):
	return SHA256.new(content)

print("Hashing time")
with CodeTimer():
	digest1=hashit(msg1)

print("\n\n verification time")
with CodeTimer():
	verify1(sig1,digest1)

s.close()	 
