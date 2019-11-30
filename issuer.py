from flask import Flask
from flask_restplus import Resource,Api

app = Flask(__name__)
api = Api(app)

@api.route('/currentAccumulator')
class CurrentAccumulator(Resource):
    def get(self):
        return {'hello': 'world'}


if __name__ == '__main__':
    app.run(debug=True)