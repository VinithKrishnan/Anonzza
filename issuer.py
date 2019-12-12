from flask import Flask,  jsonify,request
from flask_restplus import Resource,Api,fields
from werkzeug.contrib.fixers import ProxyFix
from accumulator import Accumulator,AccumulatorEncoder
from Crypto.PublicKey import RSA
from Crypto.Random.random import randint
from credential import AnonymousCredential,NamedCredential,CredentialEncoder
from user_obj import UserObject
import json
import ast

#issuer key laoding
key = RSA.generate(2048)
private_key = RSA.import_key(open("private.pem").read()).exportKey()
public_key = recipient_key = RSA.import_key(open("receiver.pem").read()).exportKey()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
api = Api(app, version='1.0', title='AnonCred API',
    description='AnonCred API',
)

ns = api.namespace('iss_opps', description='Issuer operations')
course_enr = api.model('Course_Enr', {
    'netid': fields.String(required=True, description='NetId'),
    'courses':fields.List(fields.String)
})


named_cred = api.model('NamedCred',{
    'uuid':fields.Integer,
    'name':fields.String,
    'user_type':fields.String,
    'courses':fields.List(fields.String),
    'signature':fields.Raw
})


acc = Accumulator()

registered_users = {}

@ns.route('/currentAccumulator')
class CurrentAccumulator(Resource):
    def get(self):
        t = acc.getCurrentValue()
        return json.dumps(t)

@ns.route('/currentNonce')
class CurrentNonce(Resource):
    def get(self):
        t = acc.getNonce()
        return json.dumps(t)

@ns.route('/Nvalue')
class CurrentNonce(Resource):
    def get(self):
        t = acc.n
        return json.dumps(t)

@ns.route('/accumulatorPrivate')
class PrivateAcc(Resource):
    def get(self):
        private_acc  = {'set':acc.set,'a0':acc.initial_acc,'n':acc.n}
        return json.dumps(private_acc)

@ns.route('/PubKey')
class getPubKey(Resource):
    def get(self):
        #print(public_key.export_key())
        #return "hi"
        return public_key.decode("utf-8")

#TODO: Add API to get credential

@ns.route('/addCourses')
class AddCourse(Resource):
    @ns.doc('add_course')
    @ns.expect(course_enr)
    def post(self):
        """TODO: Add logic to add course and update accumulator values
        input : netId, list of courses to add
        Will return a list of signed credential objects
        """

        data = ast.literal_eval(request.data.decode('utf-8'))
        user_netid = data['netid']
        new_courses = []

        for course in data['courses']:
            new_courses.append(course)


        User = registered_users[user_netid]
        prev_courses = User.courses
        final_courses = prev_courses + new_courses


        #delete prev cred from accumulator
        prev_cred_list = []
        prev_cred_list.append(User.anon_cred_id)
        prev_cred_list.append(User.named_cred_id)
        acc.removeCrendentials(prev_cred_list)

        #create new credentials
        #TODO: use uuid64 to generate cred ids
        new_anon_cred_id = randint(0,10000)
        new_anon_cred = AnonymousCredential(new_anon_cred_id,User.user_type,final_courses)
        new_named_cred_id = randint(0,10000)
        new_named_cred = NamedCredential(new_named_cred_id,User.user_type,User.name,final_courses)

        #sign credentials
        new_anon_cred.sign(RSA.import_key(private_key))
        new_named_cred.sign(RSA.import_key(private_key))

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

        return json.dumps(cred_list)

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

        for course in data['courses']:
            final_courses.remove(course)

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
        new_anon_cred.sign(RSA.import_key(private_key))
        new_named_cred.sign(RSA.import_key(private_key))

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

        return json.dumps(cred_list)

if __name__ == '__main__':
    #trusted setup
    app.run(debug=True,port=6060)
