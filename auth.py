from flask import request, redirect, url_for
from flask_restplus import abort
from credential import NamedCredential,AnonymousCredential,CredentialDecoder
import requests
import json
import ast,uuid
from user_obj import User
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
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



def check_request(req,challenge):
    proof = req['proof']
    cred = req['credential']
    nonce = req['nonce']
    decoded_cred = CredentialDecoder().object_hook(cred)#json.loads(json.dumps(cred),cls=CredentialDecoder)
    public_key=get_pubkey() #have to check datatype
    verifyVal= decoded_cred.verify(public_key)

    if verifyVal:
        print("Signature verification passed")
    else:
        print("Signature verification failed")
        return (False, None)

    #Check credential signature over here and then verify the proof of its existence in the accumulator
    #Now that we have the request in here, we can implement the rest of the logic
    acc_value = get_accumulator_value()
    N_value = get_N()

    #print("Verifier's view : ",acc_value,N_value,nonce,decoded_cred.uuid )

    if verify_membership(acc_value,decoded_cred.uuid,nonce,proof,N_value):
        print("Credential in Acc")
    else:
        print("Credential not in Acc")
        return (False, None)

    challengeResponse = req['challengeResponse']
    prover_pubkey = decoded_cred.tokenPubKey

    verifier = pkcs1_15.new(RSA.import_key(bytes.fromhex(prover_pubkey)))
    h = SHA384.new(bytes.fromhex(challenge))
    success = False

    try:
        verifier.verify(h,bytes.fromhex(challengeResponse))
        print("The challenge response is valid.")
        success = True
    except ValueError:
        print("The challenge response is not valid.")
        success = False

    user = None

    if isinstance(decoded_cred,NamedCredential):
        user = User(decoded_cred.name,decoded_cred.user_type,decoded_cred.courses)
    elif isinstance(decoded_cred,AnonymousCredential):
        user = User("Anonymous",decoded_cred.user_type,decoded_cred.courses)
    print("User", user)
    return (success, user)
