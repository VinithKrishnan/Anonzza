from flask import request
from credential import NamedCredential
import requests
import json
import ast
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
    return (r.json())

def login_required(f):
    def wrapper(*args, **kwargs):
        req = ast.literal_eval(request.data.decode("utf-8"))
        contnet = req['content']
        proof = req['proof']
        cred = req['credential']
        named_cred = NamedCredential(cred['uuid'],cred['user_type'],cred['name'],cred['courses'])
        named_cred.signature = cred['signature']
        public_key=get_pubkey() #have to check datatype
        if named_cred.verify(public_key):
            print("Signature verification passed")
        else:
            print("Signature verification failed")
            return

        #print(request.data)

        #Check credential signature over here and then verify the proof of its existence in the accumulator
        #Now that we have the request in here, we can implement the rest of the logic
        acc_value = get_accumulator_value()
        nonce_value = get_nonce()
        N_value = get_N()

        if verify_membership(acc_value,named_cred.uuid,nonce_value,proof,N_value):
            print("Credential in Acc")
        else:
            print("Credential not in Acc")
            return



        #Extract the proof portion and run it through the verifier

        return f(*args, **kwargs)
    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper
