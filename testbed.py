from pprint import pprint
import pymongo as pym
from nested_dictionaries import NestedDictionaries as nd
from pymongo.uri_parser import DEFAULT_PORT

db=pym.MongoClient("mongodb://localhost:27017/") # connecting to the local database

dab=db["test2"]   #This is the database
dac=dab["biharis"] #This is a collection


dac.create_index([("user.name",pym.TEXT)],default_language='english')
