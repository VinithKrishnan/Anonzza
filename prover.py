import requests
from auth import get_private_acc_data,get_accumulator_value,get_N
from rsa_accumulator.main import prove_membership
import json
from credential import CredentialDecoder,CredentialEncoder
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from prover_helper import do_verifier_login,add_post,get_posts

ISSUER_API_ROOT = "/"

cred_store = {'named_cred' : None, 'anon_cred' : None}
tokenPrivKeys = {'named_cred' : None, 'anon_cred' : None}
session_store = {'named_cred' : None, 'anon_cred' : None}

def init_setup():
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

    cred_store['anon_cred'] = json.loads(credList[0],cls=CredentialDecoder)
    cred_store['named_cred'] = json.loads(credList[1],cls=CredentialDecoder)

    tokenPrivKeys['anon_cred'] = anonTokenPrivKey
    tokenPrivKeys['named_cred'] = namedTokenPrivKey

def establish_session(cred_type):

    credential = cred_store[cred_type]
    #First get accumulator data from issuer
    acc = get_accumulator_value()
    private_acc = get_private_acc_data()

    n = private_acc['n']
    s = private_acc['set']
    s =  {int(k):int(v) for k,v in s.items()}
    a0 = private_acc['a0']

    #Create a proof of membership
    proof = prove_membership(a0, s, credential.uuid, n)
    nonce = s[credential.uuid]

    session = do_verifier_login(credential,proof,nonce,tokenPrivKeys[cred_type])
    session_store[cred_type] = session
    return session

init_setup()

#Setup sessions with named & anonymous tokens
anon_session = establish_session('anon_cred')

named_session = establish_session('named_cred')

#Create a new post with the anonymous token
add_post(session_store['anon_cred'],"CS432", "This is an anon post")

#Get current posts
print(get_posts(session_store['anon_cred'],"CS432"))

#Create a new post with the named token
add_post(session_store['named_cred'],"CS432", "This is a verified post")

#Get current posts
print(get_posts(session_store['anon_cred'],"CS432"))

