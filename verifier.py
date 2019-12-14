from flask import Flask,  jsonify,request, session
from flask_session import Session
from flask_restplus import Resource,Api,fields,abort
from accumulator import Accumulator,AccumulatorEncoder
from Crypto.PublicKey import RSA
from Crypto.Random.random import randint
from credential import AnonymousCredential,NamedCredential,CredentialEncoder
from user_obj import UserObject,User
import json, uuid, secrets
from auth import check_request
import ast,os

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
            print("No present session")
            abort(403)
        else:
            #Add course check here
            user = session['user']
            if request.view_args["courseid"] not in user.courses:
                print("Course not present in credential")
                abort(403)

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

@ns.doc("Used to create a new post on the bulletin board")
@ns.route('/class/<string:courseid>/addPost')
class AddPost(Resource):
    method_decorators = [login_required]
    @ns.expect(request_body)
    def post(self,courseid):
        """
        Used to create a new post on the bulletin board
        """
        
        data = ast.literal_eval(request.data.decode('utf-8'))
        if courseid not in class_posts:
            class_posts[courseid] = [{'content' : data['content'],'author' : session['user'].name}]
        else:
            class_posts[courseid].append({'content' : data['content'],'author' : session['user'].name})

@ns.doc("Used to read current posts on the  bulletin board")
@ns.route('/class/<string:courseid>/readPosts')
class ReadPosts(Resource):
    method_decorators = [login_required]
    def get(self,courseid):
        """Used to read current posts on the  bulletin board"""
        return class_posts[courseid]

@ns.route('/login')
class LoginHandler(Resource):
    @ns.doc("Used to initiate login process and obtain a challenge")
    def get(self):
        """Used to initiate login process and obtain a challenge"""
        challenge = uuid.uuid4()
        session['challenge'] = challenge.hex
        return challenge.hex
    @ns.doc("Used to complete login process by submitting challenge response and proofs")
    @ns.expect(login_msg)
    def post(self):
        """Used to complete login process by submitting challenge response and proofs"""
        req = request.json
        success, user = check_request(req,session['challenge'])
        if success:
            session['user'] = user
            return
        else:
            abort(403)

if __name__ == '__main__':
    app.run(debug=True)
