from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from Crypto.PublicKey import RSA
from json import JSONEncoder
import json


#Credential class
#UUID - int
#Type of User - enum
#Courses enrolled by the user - list

class Credential:
    def __init__(self, id, user_type,courses):
        self.uuid = id
        self.user_type = user_type
        self.courses = courses
        self.signature = ""

    def sign(self, private_key):
        #TODO: Add logic to sign credentials and set the value in the signature field
        return

    def verify(self, public_key):
        #TODO: Add logic to sign credentials and set the value in the signature field
        return

class NamedCredential(Credential):
    def __init__(self,id,user_type,name,courses):
        super(NamedCredential,self).__init__(id,user_type,courses)
        self.name = name

    def sign(self,private_key):
        msg = (str(self.uuid) + self.name + self.user_type + ''.join(self.courses)).encode()
        signer = pkcs1_15.new(private_key)
        h = SHA384.new(msg)
        self.signature = signer.sign(h).hex()
        return self.signature

    def verify(self,public_key):
        msg = (str(self.uuid) + self.name + self.user_type + ''.join(self.courses)).encode()
        verifier = pkcs1_15.new(public_key)
        h = SHA384.new(msg)
        try:
            verifier.verify(h,bytes.fromhex(self.signature))
            print("The signature is valid.")
        except (ValueError, TypeError):
            print ("The signature is not valid.")

class AnonymousCredential(Credential):
    def __init__(self,id,user_type,courses):
        super(AnonymousCredential,self).__init__(id,user_type,courses)

    def sign(self,private_key):
        msg = (str(self.uuid) + self.user_type + ''.join(self.courses)).encode()
        signer = pkcs1_15.new(private_key)
        h = SHA384.new(msg)
        self.signature = signer.sign(h).hex()
        return self.signature

    def verify(self,public_key):
        msg = (str(self.uuid) + self.user_type + ''.join(self.courses)).encode()
        verifier = pkcs1_15.new(public_key)
        h = SHA384.new(msg)
        try:
            verifier.verify(h,bytes.fromhex(self.signature))
            print("The signature is valid.")
        except (ValueError, TypeError):
            print ("The signature is not valid.")

class CredentialEncoder(JSONEncoder):
    def default(self, object):
        if isinstance(object, AnonymousCredential) or isinstance(object,NamedCredential):

            return object.__dict__

        else:
            # call base class implementation which takes care of
            # raising exceptions for unsupported types
            return json.JSONEncoder.default(self, object)
