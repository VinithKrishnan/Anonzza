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

class AnonymousCredential(Credential):
    def __init__(self,id,user_type,courses):
        super(AnonymousCredential,self).__init__(id,user_type,courses)


