from flask import Flask,  jsonify,request
from flask_restplus import Resource,Api,fields
from werkzeug.contrib.fixers import ProxyFix
from accumulator import Accumulator,AccumulatorEncoder
from Crypto.PublicKey import RSA
from Crypto.Random.random import randint
from credential import AnonymousCredential,NamedCredential,CredentialEncoder
from user_obj import UserObject
import json

#issuer key generation
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
api = Api(app, version='1.0', title='AnonCred API',
    description='AnonCred API',
)

ns = api.namespace('iss_opps', description='Issuer operations')
course_enr = api.model('Course_Enr', {
    'netid': fields.String(required=True, description='NetId'),
    'course1': fields.String(description='Course to be added/removed'),
    'course2': fields.String(description='Course to be added/removed')
})


named_cred = api.model('NamedCred',{
    'uuid':fields.Integer,
    'name':fields.String,
    'user_type':fields.String,
    'courses':fields.List(fields.String),
    'signature':fields.Raw
})


#TrustedSetup object
#n, a0, S
acc = Accumulator()

def as_credobject(dct):
    return
    #if 'name' in dct:
    #    return NamedCredential(dict['id'],dict['user_type'],dict['name'],dict['courses'])
    #else:
    #    return AnonymousCredential(dict['id'],dict['user_type'],dict['courses'])
    #return Accumulator(dict['n'],dict['initial_acc'],dict['set'],dict['current_value'])
#registered students holds a netId -> credential mapping
registered_users = {}

@ns.route('/currentAccumulator')
class CurrentAccumulator(Resource):
    def get(self):
        t = acc.getCurrentValue()
        #print(t)
        #enc = AccumulatorEncoder().encode(acc)
        #print(enc["n"])
        #j = json.dumps(enc)
        #o = json.loads(j,object_hook=as_credobject)
        #print(Type(o))
        #return j
        return json.dumps(t)



@ns.route('/addCourses')
class AddCourse(Resource):
    @ns.doc('add_course')
    @ns.expect(course_enr)
    #@ns.marshal_with(named_cred)
    def post(self):
        """TODO: Add logic to add course and update accumulator values
        input : netId, list of courses to add
        Will return a list of signed credential objects
        """
        #data = request.form
        data = api.payload
        user_netid = data['netid']
        new_courses = []
        if data['course1'] is not None:
            new_courses.append(data['course1'])
        if data['course2'] is not None:
            new_courses.append(data['course2'])

        User = registered_users[user_netid]
        prev_courses = User.courses
        final_courses = prev_courses + new_courses


        #delete prev cred from accumulator
        prev_cred_list = []
        prev_cred_list.append(User.anon_cred_id)
        prev_cred_list.append(User.named_cred_id)
        acc.removeCrendentials(prev_cred_list)

        #create new credentials
        new_anon_cred_id = randint(0,10000)
        new_anon_cred = AnonymousCredential(new_anon_cred_id,User.user_type,final_courses)
        new_named_cred_id = randint(0,10000)
        new_named_cred = NamedCredential(new_named_cred_id,User.user_type,User.name,final_courses)

        #sign credentials
        new_anon_cred.sign(private_key)
        new_named_cred.sign(private_key)

        #add new creds to accumulator
        new_cred_list=[]
        new_cred_list.append(new_anon_cred_id)
        new_cred_list.append(new_named_cred_id)
        acc.addCredentials(new_cred_list)

        #update registered_users
        User.courses=final_courses
        User.anon_cred_id=new_anon_cred_id
        User.named_cred_id=new_named_cred_id
        registered_users[user_netid]=User

        #return credentials
        cred_list=[]
        cred_list.append(CredentialEncoder().encode(new_anon_cred))
        cred_list.append(CredentialEncoder().encode(new_named_cred))
        #enc = CredentialEncoder().encode(new_anon_cred)
        #return json.dumps(enc)
        #neo_cred = {}
        #neo_cred['name']=new_named_cred.name
        #neo_cred['uuid']=new_named_cred.uuid
        #neo_cred['user_type']=new_named_cred.user_type
        #neo_cred['courses']=new_named_cred.courses
        #neo_cred['signature']=new_named_cred.signature.hex()
        #return neo_cred
        return json.dumps(cred_list)
        #return json.dumps(CredentialEncoder().encode(new_named_cred))
#test
temp_user = UserObject("vin","student",["CS432","CS534"],123,456)
registered_users["vinithk2"]=temp_user
acc.addCredentials([123,456])

@ns.route('/dropCourses')
class DropCourses(Resource):
    @ns.doc('drop_courses')
    @ns.expect(course_enr)
    def post(self):
        """TODO: Add logic to add course and update accumulator values
        Will return a list of signed credential objects
        input : netId, list of courses to drop
        """
        data = api.payload
        user_netid = data['netid']

        User = registered_users[user_netid]
        prev_courses = User.courses
        final_courses = prev_courses
        #print(final_courses)
        if data['course1'] is not None:
            final_courses.remove(data['course1'])
        if data['course2'] is not None:
            final_courses.remove(data['course2'])



        #delete prev cred from accumulator
        prev_cred_list = []
        prev_cred_list.append(User.anon_cred_id)
        prev_cred_list.append(User.named_cred_id)
        acc.removeCrendentials(prev_cred_list)

        #create new credentials
        new_anon_cred_id = randint(0,10000)
        new_anon_cred = AnonymousCredential(new_anon_cred_id,User.user_type,final_courses)
        new_named_cred_id = randint(0,10000)
        new_named_cred = NamedCredential(new_named_cred_id,User.user_type,User.name,final_courses)

        #sign credentials
        new_anon_cred.sign(private_key)
        new_named_cred.sign(private_key)

        #add new creds to accumulator
        new_cred_list=[]
        new_cred_list.append(new_anon_cred_id)
        new_cred_list.append(new_named_cred_id)
        acc.addCredentials(new_cred_list)

        #update registered_users
        User.courses=final_courses
        User.anon_cred_id=new_anon_cred_id
        User.named_cred_id=new_named_cred_id
        registered_users[user_netid]=User

        #return credentials
        cred_list=[]
        cred_list.append(CredentialEncoder().encode(new_anon_cred))
        cred_list.append(CredentialEncoder().encode(new_anon_cred))
        #enc = CredentialEncoder().encode(new_anon_cred)
        #return json.dumps(enc)
        #print (new_named_cred.signature)
        #neo_cred['name']=new_named_cred.name
        #neo_cred['uuid']=new_named_cred.uuid
        #neo_cred['user_type']=new_named_cred.user_type
        #neo_cred['courses']=new_named_cred.courses
        #neo_cred['signature']=new_named_cred.signature.hex()
        #return neo_cred
        return json.dumps(cred_list)

if __name__ == '__main__':
    #trusted setup
    app.run(debug=True)
