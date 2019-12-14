import requests
from auth import get_private_acc_data,get_accumulator_value,get_N
from rsa_accumulator.main import prove_membership
import json
from credential import CredentialDecoder,CredentialEncoder
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from prover_helper import do_verifier_login,add_post,get_posts
from issuer import registered_users
ISSUER_API_ROOT = "/"

cred_store = {'named_cred' : None, 'anon_cred' : None}
tokenPrivKeys = {'named_cred' : None, 'anon_cred' : None}
session_store = {'named_cred' : None, 'anon_cred' : None}

def init_setup(netid):
    #Get credentials from the issuer
    #Setup 2 keys for receiving 2 tokens from the receiver
    anonTokenKeyPair = RSA.generate(2048)
    anonTokenPrivKey = anonTokenKeyPair.exportKey()
    anonTokenPubKey = recipient_key = anonTokenKeyPair.publickey().exportKey()


    namedTokenKeyPair = RSA.generate(2048)
    namedTokenPrivKey = namedTokenKeyPair.exportKey()
    namedTokenPubKey = recipient_key = namedTokenKeyPair.publickey().exportKey()

    #
    req = requests.post("http://127.0.0.1:6060/iss_opps/getCred/"+netid,json = {'namedKey':namedTokenPubKey.hex(),'anonKey':anonTokenPubKey.hex()})


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

# Added initial user to issuer's database for testing
# In the real world issuer would already have an internal databse containing user details
requests.post("http://127.0.0.1:6060/iss_opps/addUser",json = {
'netId':"vinithk2",
'name':"Vinith",
'user_type':"student",
'courses':["CS432","CS534"],
'anon_cred_id':123,#dummy credid
'named_cred_id':456})#dummy credid

#initializes session for user with netid in temp_netid
temp_netid = "vinithk2"
init_setup(temp_netid)

#Setup sessions with named & anonymous tokens
anon_session = establish_session('anon_cred')

named_session = establish_session('named_cred')

#Create a new post with the anonymous token
add_post(session_store['anon_cred'],"CS432", "This is an anon post for cs432")

#Get current posts
print("Get posts1:")
print(get_posts(session_store['anon_cred'],"CS432"))

#Create a new post with the named token
add_post(session_store['named_cred'],"CS432", "This is a verified post for cs432")

#Get current posts
print("Get posts2:")
print(get_posts(session_store['anon_cred'],"CS432"))

#add courses
requests.post("http://127.0.0.1:6060/iss_opps/addCourses",json={
'netid':"vinithk2",
'courses':["CS241","CS451"]
})

#setup after adding courses
init_setup(temp_netid)

#Setup sessions with named & anonymous tokens
anon_session = establish_session('anon_cred')

named_session = establish_session('named_cred')

#Create a new post with the anonymous token
add_post(session_store['anon_cred'],"CS241", "This is an anon post for CS241")

#Get current posts
print("Get posts3:")
print(get_posts(session_store['anon_cred'],"CS241"))

#Create a new post with the named token
add_post(session_store['named_cred'],"CS241", "This is a verified post for CS241")

#Get current posts
print("Get posts4:")
print(get_posts(session_store['anon_cred'],"CS241"))

#drop courses
requests.post("http://127.0.0.1:6060/iss_opps/dropCourses",json={
'netid':"vinithk2",
'courses':["CS241"]
})

init_setup(temp_netid)

#Setup sessions with named & anonymous tokens
anon_session = establish_session('anon_cred')

named_session = establish_session('named_cred')

#Create a new post with the anonymous token
#(should fail since user has dropped course CS241!)
#Uncomment below code to see error
#add_post(session_store['anon_cred'],"CS241", "This is an anon post")
