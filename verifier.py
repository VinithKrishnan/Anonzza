from flask import Flask,  jsonify,request
from flask_restplus import Resource,Api,fields
from accumulator import Accumulator,AccumulatorEncoder
from Crypto.PublicKey import RSA
from Crypto.Random.random import randint
from credential import AnonymousCredential,NamedCredential,CredentialEncoder
from user_obj import UserObject
import json
from auth import login_required

app = Flask(__name__)
api = Api(app, version='1.0', title='Verifier API',
    description='Verifier API',
)

ns = api.namespace('ver_opps', description='Verifier operations')

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
    'proof' : fields.Integer
})




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