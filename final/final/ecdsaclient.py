import socket			 
from linetimer import CodeTimer
from Crypto.Hash import SHA256
import time
from ecdsa import SigningKey, SECP256k1, VerifyingKey
s = socket.socket()		 

port = 10004				

s.connect(('10.0.0.1', port)) 

x = s.recv(1108)
msg1 = x[:1044]
sig1 = x[1044:]
print(msg1.decode())
print(sig1)
print(len(msg1))
print(len(sig1))

#Verify signature
with open("ecdsakey.pem","rb") as f:
	vk_string=f.read()
	vk = VerifyingKey.from_string(vk_string,curve=SECP256k1)

def verify1(content,signature):
	vk.verify(signature,content)

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
	f.write("ECDSA Hashing time " +str(hashingtime)+"\n"+ "ECDSA verification time " + str(verificationtime)+"\n")

s.close()	 
