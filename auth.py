from flask import request


def login_required(f):
    def wrapper(*args, **kwargs):
        print(request.data)
        #Check credential signature over here and then verify the proof of its existence in the accumulator
        #Now that we have the request in here, we can implement the rest of the logic
        return f(*args, **kwargs)
    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper