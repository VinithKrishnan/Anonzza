from flask import request
import requests
import json

def get_accumulator_value():
    r = requests.get('http://127.0.0.1:6060/iss_opps/currentAccumulator')
    return int(r.json())

def login_required(f):
    def wrapper(*args, **kwargs):
        print(request.data)
        #Check credential signature over here and then verify the proof of its existence in the accumulator
        #Now that we have the request in here, we can implement the rest of the logic
        acc_value = get_accumulator_value()
        #Extract the proof portion and run it through the verifier

        return f(*args, **kwargs)
    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper