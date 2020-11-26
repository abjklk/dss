import socket			 
from linetimer import CodeTimer
from Crypto.Hash import SHA256
import ed25519
import time
s = socket.socket()		 

port = 10005				

s.connect(('10.0.0.1', port)) 

x = s.recv(1172)
msg1 = x[:1044]
sig1 = x[1044:]
print(msg1.decode())
print(sig1)

#Verify signature
with open("eddsakey.pem","rb") as f:
	pubKey = ed25519.VerifyingKey(f.read())


def verify1(content,signature):
	 pubKey.verify(signature, content, encoding='hex')

def hashit(content):
	return SHA256.new(content).digest()

print("Hashing time")
t0=time.time()
digest1=hashit(msg1)
t1=time.time()
hashingtime=(t1-t0)*1000

print("\n\n verification time")
t0=time.time()
verify1(digest1,sig1)
t1=time.time()
verificationtime=(t1-t0)*1000

with open("results.txt","a") as f:
	f.write("EDDSA Hashing time " +str(hashingtime)+ "EDDSA verification time " + str(verificationtime)+"\n")

s.close()	 
