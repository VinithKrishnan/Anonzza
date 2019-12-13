from credential import CredentialEncoder
import requests, json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384

def do_verifier_login(credential,proof,nonce,tokenPrivateKey):
    session = requests.Session()

    req1 = session.get("http://127.0.0.1:5000/ver_opps/login")
    if req1.status_code != 200:
        raise ConnectionError
    
    challenge = bytes.fromhex(req1.json())
    signer = pkcs1_15.new(RSA.import_key(tokenPrivateKey))
    h = SHA384.new(challenge)
    challengeResponse = signer.sign(h).hex()

    req2 = session.post("http://127.0.0.1:5000/ver_opps/login",
                              data=json.dumps({'credential':credential,'proof':proof,'nonce':nonce,'challengeResponse':challengeResponse},
                              cls=CredentialEncoder),
                              headers={'content-type':'application/json'})
    if req2.status_code == 200:
        return session

def add_post(session,course,content):
    req = session.post("http://127.0.0.1:5000/ver_opps/class/"+course + "/addPost",json = {'content':content})
    if req.status_code != 200:
        raise ConnectionError

def get_posts(session,course):
    req = session.get("http://127.0.0.1:5000/ver_opps/class/"+course + "/readPosts")
    if req.status_code != 200:
        raise ConnectionError
    return req.json()

