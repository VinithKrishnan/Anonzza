from rsa_accumulator.main import setup,add,delete
from json import JSONEncoder
import json

class Accumulator:
    def __init__(self):
        n,a0,s = setup()

        self.n = n
        self.initial_acc = a0
        self.set = s
        self.current_value = a0

    def __repr__(self):
        return json.dumps(self.__dict__)

    def addCredentials(self,credential_ids):
        #Bulk add the given ids
        acc_final = self.current_value
        for id in credential_ids:
            acc_final = add(acc_final,self.set,id,self.n)
        self.current_value = acc_final

        return

    def removeCrendentials(self, credential_ids):
        #Bulk delete the given ids
        acc_final = self.current_value
        for id in credential_ids:
            acc_final = delete(self.initial_acc,acc_final,self.set,id,self.n)
        self.current_value=acc_final
        return

    def getCurrentValue(self):
        #Return N and the current acc value
        return self.current_value

class AccumulatorEncoder(JSONEncoder):
    def default(self, object):
        if isinstance(object, Accumulator):

            return object.__dict__

        else:
            # call base class implementation which takes care of
            # raising exceptions for unsupported types
            return json.JSONEncoder.default(self, object)

    #TODO: Find a way to decode/encode to JSON
