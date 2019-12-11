import requests
from auth import get_private_acc_data,get_accumulator_value,get_N
from rsa_accumulator.main import prove_membership
import json
from credential import CredentialDecoder,CredentialEncoder

ISSUER_API_ROOT = "/"

req = requests.post("http://127.0.0.1:6060/iss_opps/addCourses",data = json.dumps({'netid':'vinithk2','course1':'c1','course2':'c2'}))

credList = json.loads(req.json())

anon_cred = json.loads(credList[0],cls=CredentialDecoder)
named_cred = json.loads(credList[1],cls=CredentialDecoder)

print(anon_cred.signature)
acc = get_accumulator_value()

private_acc = get_private_acc_data()

n = private_acc['n']
s = private_acc['set']
s =  {int(k):int(v) for k,v in s.items()}
a0 = private_acc['a0']

print(n,s,a0)

proof = prove_membership(a0, s, named_cred.uuid, n)
nonce = s[named_cred.uuid]
print(proof)

req1 = requests.post("http://127.0.0.1:5000/ver_opps/currentAccumulator",data = json.dumps({'content':'Test post','credential':named_cred,'proof':proof,'nonce':nonce},cls=CredentialEncoder))

