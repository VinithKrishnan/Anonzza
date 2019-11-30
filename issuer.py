from flask import Flask,  jsonify
from flask_restplus import Resource,Api
from accumulator import Accumulator
import json

app = Flask(__name__)
api = Api(app)

#TrustedSetup object
#n, a0, S
acc = Accumulator()

#registered students holds a netId -> credential mapping
registered_students = {}

@api.route('/currentAccumulator')
class CurrentAccumulator(Resource):
    def get(self):
        return acc.getCurrentValue()


@api.route('/addCourses')
class AddCourse(Resource):
    def post(self):
        """TODO: Add logic to add course and update accumulator values
        input : netId, list of courses to add
        Will return a list of signed credential objects
        """

@api.route('/dropCourses')
class DropCourses(Resource):
    def post(self):
        """TODO: Add logic to add course and update accumulator values
        Will return a list of signed credential objects
        input : netId, list of courses to drop
        """

if __name__ == '__main__':
    #trusted setup
    app.run(debug=True)