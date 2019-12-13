import requests
from auth import get_private_acc_data,get_accumulator_value,get_N
from rsa_accumulator.main import prove_membership
import json
from credential import CredentialDecoder,CredentialEncoder
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384

ISSUER_API_ROOT = "/"

#Get credentials from the issuer
#Setup 2 keys for receiving 2 tokens from the receiver
anonTokenKeyPair = RSA.generate(2048)
anonTokenPrivKey = anonTokenKeyPair.exportKey()
anonTokenPubKey = recipient_key = anonTokenKeyPair.publickey().exportKey()

namedTokenKeyPair = RSA.generate(2048)
namedTokenPrivKey = namedTokenKeyPair.exportKey()
namedTokenPubKey = recipient_key = namedTokenKeyPair.publickey().exportKey()

req = requests.post("http://127.0.0.1:6060/iss_opps/getCred/vinithk2",json = {'namedKey':namedTokenPubKey.hex(),'anonKey':anonTokenPubKey.hex()})

credList = req.json()

anon_cred = json.loads(credList[0],cls=CredentialDecoder)
named_cred = json.loads(credList[1],cls=CredentialDecoder)

acc = get_accumulator_value()

private_acc = get_private_acc_data()

n = private_acc['n']
s = private_acc['set']
s =  {int(k):int(v) for k,v in s.items()}
a0 = private_acc['a0']

print(n,s,a0)

proof = prove_membership(a0, s, anon_cred.uuid, n)
nonce = s[anon_cred.uuid]
print(proof)

print("Acc values",a0,s,n,acc)



anon_session = requests.Session()

req1 = anon_session.get("http://127.0.0.1:5000/ver_opps/login")
challenge = bytes.fromhex(req1.json())
signer = pkcs1_15.new(RSA.import_key(anonTokenPrivKey))
h = SHA384.new(challenge)
challengeResponse = signer.sign(h).hex()


req2 = anon_session.post("http://127.0.0.1:5000/ver_opps/login",data=json.dumps({'credential':anon_cred,'proof':proof,'nonce':nonce,'challengeResponse':challengeResponse},cls=CredentialEncoder),headers={'content-type':'application/json'})
print(req2.json())

req3 = anon_session.post("http://127.0.0.1:5000/ver_opps/class/CS432/addPost",json = {'content':"This is an anon post!"})
print(req3.json())

req4 = anon_session.get("http://127.0.0.1:5000/ver_opps/class/CS432/readPosts")
print(req4.json())


regular_session = requests.Session()

req1 = regular_session.get("http://127.0.0.1:5000/ver_opps/login")
challenge = bytes.fromhex(req1.json())
signer = pkcs1_15.new(RSA.import_key(namedTokenPrivKey))
h = SHA384.new(challenge)
challengeResponse = signer.sign(h).hex()
proof = prove_membership(a0, s, named_cred.uuid, n)
nonce = s[named_cred.uuid]

req2 = regular_session.post("http://127.0.0.1:5000/ver_opps/login",data=json.dumps({'credential':named_cred,'proof':proof,'nonce':nonce,'challengeResponse':challengeResponse},cls=CredentialEncoder),headers={'content-type':'application/json'})
print(req2.json())

req3 = regular_session.post("http://127.0.0.1:5000/ver_opps/class/CS432/addPost",json = {'content':"This is a regular post!"})
print(req3.json())

req4 = regular_session.get("http://127.0.0.1:5000/ver_opps/class/CS432/readPosts")
print(req4.json())

