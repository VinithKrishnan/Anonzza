from flask import Flask,  jsonify,request
from flask_restplus import Resource,Api,fields
from accumulator import Accumulator,AccumulatorEncoder
from Crypto.PublicKey import RSA
from Crypto.Random.random import randint
from credential import AnonymousCredential,NamedCredential,CredentialEncoder
from user_obj import UserObject
import json
from auth import login_required
import ast

app = Flask(__name__)
api = Api(app, version='1.0', title='Verifier API',
    description='Verifier API',
)

ns = api.namespace('ver_opps', description='Verifier operations')

class_posts = {}

named_cred = api.model('NamedCred',{
    'uuid':fields.Integer,
    'name':fields.String,
    'user_type':fields.String,
    'courses':fields.List(fields.String),
    'signature':fields.Raw
})

request_body = api.model('RequestBody',{
    'content':fields.String,
    'credential' : fields.Nested(named_cred),
    'proof' : fields.Integer,
    'nonce' : fields.Integer
})

#TODO: Apis to add posts -> /class/:className/posts
"""
@ns.route('/class/<string:courseid>/addPost')
class AddPost(Resource):
    method_decorators = [login_required]
    @ns.expect(request_body)
    def post(self,courseid):
        data = ast.literal_eval(request.data.decode('utf-8')
        if len(class_posts)==0 :
            class_posts[courseid] = [data['content']]
        else:
            class_posts[courseid].append(data['content'])

@ns.route('/class/<string:courseid>/readPosts')
class ReadPosts(Resource):
    method_decorators = [login_required]
    @ns.expect(request_body)
    def post(self,courseid):
        if len(class_posts)==0 :
            print("No posts yet!")
        else:
            print(class_posts[courseid])
"""






@ns.route('/currentAccumulator')
class CurrentAccumulator(Resource):
    method_decorators = [login_required]
    @ns.expect(request_body)
    def post(self):
        print("Hi there")
        return "Hello"

if __name__ == '__main__':
    #trusted setup
    app.run(debug=True)
