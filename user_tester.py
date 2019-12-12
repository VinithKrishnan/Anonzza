from Crypto.PublicKey import RSA

#ignore
#r = requests.post('http://127.0.0.1:6060/iss_opps/addCourses')
#print(r)
key = RSA.generate(2048)
private_key = key.exportKey()
file_out = open("private.pem", "wb")
file_out.write(private_key)

public_key = key.publickey().exportKey()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
