from flask import Flask,  jsonify,request, session
from flask_session import Session
from flask_restplus import Resource,Api,fields,abort
from accumulator import Accumulator,AccumulatorEncoder
from Crypto.PublicKey import RSA
from Crypto.Random.random import randint
from credential import AnonymousCredential,NamedCredential,CredentialEncoder
from user_obj import UserObject
import json, uuid, secrets
from auth import check_request
import ast,os
from flask_login import LoginManager

app = Flask(__name__)


api = Api(app, version='1.0', title='Verifier API',
    description='Verifier API',
)
app.secret_key = 'dev'
sess = Session()
app.config['SESSION_TYPE'] = 'filesystem'
sess.init_app(app)




ns = api.namespace('ver_opps', description='Verifier operations')

Users = {}

class_posts = {}

def login_required(f):
    def wrapper(*args, **kwargs):
        #Extract the proof portion and run it through the verifier
        if session['user'] is None:
            abort(403)
        else:
            #Add course check here
            user = session['user']
            
            
        return f(*args, **kwargs)
    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper

named_cred = api.model('NamedCred',{
    'uuid':fields.Integer,
    'name':fields.String,
    'user_type':fields.String,
    'courses':fields.List(fields.String),
    'signature':fields.Raw
})

request_body = api.model('RequestBody',{
    'content':fields.String,
    
})

login_msg = api.model('LoginBody',{
    'credential' : fields.Nested(named_cred),
    'proof' : fields.Integer,
    'nonce' : fields.Integer,
    'challengeResponse': fields.String
})

@ns.route('/class/<string:courseid>/addPost')
class AddPost(Resource):
    method_decorators = [login_required]
    @ns.expect(request_body)
    def post(self,courseid):
        data = ast.literal_eval(request.data.decode('utf-8'))
        if len(class_posts) == 0:
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


@ns.route('/login')
class LoginHandler(Resource):
    def get(self):
        challenge = uuid.uuid4()
        session['challenge'] = challenge.hex
        return challenge.hex
    @ns.expect(login_msg)
    def post(self):
        req = request.json
        success, user = check_request(req)
        if success:
            session['user'] = user
            return
        else:
            abort(403)

if __name__ == '__main__':
    #trusted setup
    app.run(debug=True)
