from flask import request, redirect, url_for
from flask_restplus import abort
from credential import NamedCredential,AnonymousCredential,CredentialDecoder
import requests
import json
import ast,uuid
from user_obj import User
from Crypto.PublicKey import RSA
from rsa_accumulator.main import verify_membership,__verify_membership

def get_accumulator_value():
    r = requests.get('http://127.0.0.1:6060/iss_opps/currentAccumulator')
    return int(r.json())

def get_nonce():
    r = requests.get('http://127.0.0.1:6060/iss_opps/currentNonce')
    return int(r.json())

def get_N():
    r = requests.get('http://127.0.0.1:6060/iss_opps/Nvalue')
    return int(r.json())

def get_pubkey():
    r = requests.get('http://127.0.0.1:6060/iss_opps/PubKey')
    key = RSA.import_key(r.json())
    return key

def get_private_acc_data():
    r = requests.get('http://127.0.0.1:6060/iss_opps/accumulatorPrivate')
    return json.loads((r.json()))



def check_request(req):
    proof = req['proof']
    cred = req['credential']
    nonce = req['nonce']
    decoded_cred = CredentialDecoder().object_hook(cred)#json.loads(json.dumps(cred),cls=CredentialDecoder)
    public_key=get_pubkey() #have to check datatype
    verifyVal= decoded_cred.verify(public_key)
    print(verifyVal)
    if verifyVal:
        print("Signature verification passed")
    else:
        print("Signature verification failed")
        return (False, None)

    #Check credential signature over here and then verify the proof of its existence in the accumulator
    #Now that we have the request in here, we can implement the rest of the logic
    acc_value = get_accumulator_value()
    N_value = get_N()

    if verify_membership(acc_value,decoded_cred.uuid,nonce,proof,N_value):
        print("Credential in Acc")
    else:
        print("Credential not in Acc")
        return (False, None)

    #TODO: Check if the challenge is the correct value

    name = None
    if isinstance(cred,NamedCredential):
        name = User(cred.name,cred.user_type,cred.courses)
    elif isinstance(cred,AnonymousCredential):
        name = User("Anonymous",cred.user_type,cred.courses)

    return (True, name)
