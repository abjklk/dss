import socket			 
from linetimer import CodeTimer
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import DSA
import time
s = socket.socket()		 

port = 10003				

s.connect(('10.0.0.1', port)) 

x = s.recv(1084)
msg1 = x[:1044]
sig1 = x[1044:]
print(msg1.decode())
print(sig1)

#Verify signature
with open("dsskey.pem") as f:
	publickey = DSA.import_key(f.read())

def verify1(signature,content):	
	pkey=DSS.new(publickey,'fips-186-3')
	pkey.verify(content,signature)

def hashit(content):
	return SHA256.new(content)

print(" DSS Hashing time")
t0=time.time()
digest1=hashit(msg1)
t1=time.time()
hashingtime=(t1-t0)*1000

print("\n\n DSS verification time")
t0=time.time()
verify1(sig1,digest1)
t1=time.time()
verificationtime=(t1-t0)*1000

with open("results.txt","a") as f:
	f.write("DSS Hashing time " +str(hashingtime)+ "DSS verification time " + str(verificationtime)+"\n")

s.close()	 
