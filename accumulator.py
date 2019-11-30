from rsa_accumulator.main import setup
import json

class Accumulator:
    def __init__(self):
        n,a0,s = setup()
        
        self.n = n
        self.initial_acc = a0
        self.set = s
        self.curent_value = a0

    def __repr__(self):
        return json.dumps(self.__dict__)

    def addCredentials(self,credential_ids):
        #Bulk add the given ids
        return 

    def removeCrendentials(self, credential_ids):
        #Bulk delete the given ids
        return

    def getCurrentValue(self):
        #Return N and the current acc value
        return

    #TODO: Find a way to decode/encode to JSON

