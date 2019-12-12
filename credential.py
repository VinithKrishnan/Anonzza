from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from Crypto.PublicKey import RSA
from json import JSONEncoder,JSONDecoder
import json


#Credential class
#UUID - int
#Type of User - enum
#Courses enrolled by the user - list

class Credential:

    def __init__(self, id, user_type,courses,signature,tokenPubKey):
        self.uuid = id
        self.user_type = user_type
        self.courses = courses
        self.signature = signature
        self.tokenPubKey = tokenPubKey

    def sign(self,msg, private_key):
        signer = pkcs1_15.new(private_key)
        h = SHA384.new(msg)
        self.signature = signer.sign(h).hex()
        return self.signature

    def verify(self, msg,public_key):
        verifier = pkcs1_15.new(public_key)
        h = SHA384.new(msg)
        success = False
       
        try:
            verifier.verify(h,bytes.fromhex(self.signature))
            print("The signature is valid.")
            success = True
        except ValueError:
            print ("The signature is not valid.")
            success = False

        print("Check value for signature verification",success)
        return success

class NamedCredential(Credential):
    def __init__(self,uuid,user_type,name,courses,signature="",tokenPubKey = ""):
        super(NamedCredential,self).__init__(uuid,user_type,courses,signature,tokenPubKey)
        self.name = name

    def sign(self,private_key):
        msg = (str(self.uuid) + self.name + self.user_type + self.tokenPubKey + ''.join(self.courses)).encode()
        super(NamedCredential,self).sign(msg,private_key)

    def verify(self,public_key):
        msg = (str(self.uuid) + self.name + self.user_type + self.tokenPubKey + ''.join(self.courses)).encode()
        return super(NamedCredential,self).verify(msg,public_key) 

class AnonymousCredential(Credential):

    def __init__(self,uuid,user_type,courses,signature="",tokenPubKey = ""):
        super(AnonymousCredential,self).__init__(uuid,user_type,courses,signature,tokenPubKey)

    def sign(self,private_key):
        msg = (str(self.uuid) + self.user_type + self.tokenPubKey + ''.join(self.courses)).encode()
        super(AnonymousCredential,self).sign(msg,private_key)

    def verify(self,public_key):
        msg = (str(self.uuid) + self.user_type + self.tokenPubKey + ''.join(self.courses)).encode()
        return super(AnonymousCredential,self).verify(msg,public_key)

class CredentialEncoder(JSONEncoder):
    def default(self, object):
        if isinstance(object, AnonymousCredential) or isinstance(object,NamedCredential):
            obj_dict = {
                "__class__" : object.__class__.__name__,
                "__module__" : object.__module__
            }
            obj_dict.update(object.__dict__)
            return obj_dict

        else:
            # call base class implementation which takes care of
            # raising exceptions for unsupported types
            return json.JSONEncoder.default(self, object)

class CredentialDecoder(JSONDecoder):
    def __init__(self):
        return

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        if '__class__' not in obj:
            return obj
        class_name = obj.pop("__class__")
        module_name = obj.pop("__module__")

        module = __import__(module_name)
        
        class_ = getattr(module,class_name)

        newObj = class_(**obj)

        return newObj
        