#This works fine
import json
import rsa
from nested_dictionaries import NestedDictionaries as nd
import flask
import pymongo as pym
from hashlib import sha256,md5
from pyaes import AESModeOfOperationCTR
from Crypto.Random import get_random_bytes
from secrets import token_hex
import time
from bson.objectid import ObjectId
#EVERYTHING IS UTF-8

#######################--3-Level Dictionary concater and decryptor################################################
def gav(nested_dictionary): #concates all the values in a two nested dictionary
  a=b""
  for key, value in nested_dictionary.items():
    try:
     a=a+value 
    except:
     try:   
      for key2 in value:
       a=a+value[key2]
     except:
      for key3 in value[key2]:
        a=a+value[key2][key3]      
  return(a)###'a' returns the concated valye while 'b' returns the decoded dictionary 
#######################--3-Level Dictionary concater and aes decryptor################################################

#########################Initialization of asserting variables##################################
gender=["male","female","other","Apache attack helicopter"] #Add in genders here
occupation=["","",""]                                       #Add in occupations here
accemails=["gmail","yahoo","rocketmail"]                    #Add in acceptable email domains
states=["Telangana","Andhra Pradesh"]
countries=["India","Sweden"]
#########################Initialization of asserting variables##################################

app=flask.Flask(__name__)
db=pym.MongoClient("mongodb://localhost:27017/") # connecting to the local Mongodb
app.config['MAX_CONTENT_LENGTH'] = 13 * 1000 * 1000

@app.route('/api/register',methods=['POST'])
def register(): 
    
    try:        
        try:
                data=flask.request.data
                data=flask.request.get_json() # Simply puts the JSON_data which I got into the data var
                
        #####################Check the content here#################################################        
                assert int((data["user"]["age"])) <= 120 and type(data["user"]["age"])==str                              #Defending against stupid attacks     
                assert data["user"]["sex"] in gender and type(data["user"]["sex"])==str 
                assert len(data["user"]["password"])==19 and type(data["user"]["password"])==str#Defending against stupid attacks
                assert len(data["user"]["email"])<40 and type(data["user"]["email"])==str                                 #Defending against stupid attacks
                assert len(data["user"]["occupation"])<20 and type(data["user"]["occupation"])==str                             #Defending against stupid attacks
                assert len(data["user"]["politicalleaning"])<15 and type(data["user"]["politicalleaning"])==str                      #Defending against stupid attacks
                assert len(data["user"]["supporting party"]["name"])<50 and type(data["user"]["supporting party"]["name"])==str              #Defending against stupid attacks
                assert int(data["user"]["supporting party"]["chance"])<=100 and type(data["user"]["supporting party"]["chance"])==str            #Defending against stupid attacks 
                assert len(data["user"]["Election circles"])<=10 and type(data["user"]["Election circles"])==list                                   #Defending against stupid attacks
                for i in data["user"]["Election circles"]:assert type(i)==str
                assert len(data["user"]["phone"])<=10 and len(data["user"]["phone"])>8 and type(data["user"]["phone"])==int #Defending against stupid attacks
                assert type(data["user"]["state"])==str
                assert type(data["user"]["nation"])==str and len(data["user"]["nation"])<=25
                assert type(data["user"]["name"])==str and 3<len(data["user"]["name"])<20 
                assert data["user"]["nation"] in countries ###Change to database
        except:
                return {"Error":"Error in assertions"}   
        
        
        
        
        #####################Check the content here################################################# 
        
        #################Expected contents(Add Here to upgrade)#####################################################    
        me=nd()
        me["user"]["email"]=data["user"]["email"]                                          #1
        me["user"]["password"]=data["user"]["password"]                                    #2
        me["user"]["age"]=data["user"]["age"]                                              #3
        me["user"]["sex"]=data["user"]["sex"]                                              #4
        me["user"]["occupation"]=data["user"]["occupation"]                                #5 
        me["user"]["Political Leaning"]=data["user"]["politicalleaning"]                   #6
        me["user"]["supporting party"]["name"]=data["user"]["supporting party"]["name"]    #7
        me["user"]["supporting party"]["chance"]=data["user"]["supporting party"]["chance"]#8
        me["user"]["election circles"]=data["user"]["election circles"]                    #9
        me["user"]["state"]=data["user"]["state"]                                          #10
        me["user"]["phone"]=data["user"]["phone"]                                          #11
        me["user"]["nation"]=data["user"]["nation"]                                        #12
        me["user"]["name"]=data["user"]["name"]                                            #13
        
        #################Expected contents(Add Here to upgrade)#####################################################          

                
        x=me["user"]["email"].split("@")        #Seperating the username from domain
        x1=x[1].split(".")                      #seperating the domain and .
        
        name=x[0]                #Assingning the starting name to the name
        edomain=x1[0]            #Assigning the domain to the domain
        
        assert edomain in accemails   #Hopefully he has email which is verified    
        
        tes=md5((data["user"]["password"]).encode('utf-8'))
        me["user"]["password"]=tes.hexdigest()
        
        
        dab=db["users"]          #This is the users data database
        dac=dab[me["user"]["state"]]                     #This is a collection
        
        
        try:
            assert dac.find_one({"user.email":data["user"]["email"]})==None          #Checking for existing users
        except:
            return {"Error":"User already exists"}
        
        dac.insert_one(me)                   #Inserts the email and password into the required collection
        return {"Operation Status":"Successful"}
    except:     
       return {"Error":"Check if all the contents are exact"}  


@app.route('/api/captcha',methods=['GET'])
def capgen():
   