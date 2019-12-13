from flask_login import UserMixin

class UserObject:
    def __init__(self,name,user_type,courses,anon_cred_id,named_cred_id):
        self.name=name
        self.user_type=user_type
        self.courses=courses
        self.anon_cred_id=anon_cred_id
        self.named_cred_id=named_cred_id

class User:
    def __init__(self,name,user_type,courses):
        self.name = name
        self.user_type = user_type
        self.courses = courses
