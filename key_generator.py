from Crypto.PublicKey import RSA
from credential import Credential,NamedCredential,AnonymousCredential



#key generation
key = RSA.generate(2048)
private_key = key
#file_out = open("private.pem", "wb")
#file_out.write(private_key)

public_key = key.publickey()
#file_out = open("receiver.pem", "wb")
#file_out.write(public_key)

cred = NamedCredential("123","student","HAL","CS432")
cred.sign(private_key)
cred.verify(public_key)
