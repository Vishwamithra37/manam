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
        
        dab=db["users"]          #This is the users data database
        dac=dab[me["user"]["state"]]                     #This is a collection
        dad=dac[name]                        #This is the document named by the hexdigest number
        
        try:
            assert dad.find_one()==None          #Checking for existing users
        except:
            return {"Error":"User already exists"}
        
        dad.insert_one(me)                   #Inserts the email and password into the required collection
        return {"Operation Status":"Successful"}
    except:     
       return {"Error":"Check if all the contents are exact"}  

@app.route('/api/login',methods=['POST'])
def tokens():
    try:
        data=flask.request.data
        data=flask.request.get_json()  
        
        assert len(data["user"]["email"])<40 and type(data["user"]["email"])==str
        assert type(data["user"]["state"])==str and len(data["user"]["state"])<=40
    ###################################### Add captcha ################################################    
    ###################################### Add captcha ###############################################   
        x=data["user"]["email"].split("@")      #Seperating the username from domain
        x1=x[1].split(".")                      #seperating the domain and .
        name=x[0]                               #Assingning the starting name to the name
        edomain=x1[0]                           #Assigning the domain to the domain
         
        
        assert edomain in accemails             #Cheking if the email exists at all        
        
        tes=md5((data["user"]["password"]).encode('utf-8'))
        
        
        dab=db["users"]                         #This is the database
        dac=dab[data["user"]["state"]]          #This is a collection
        dad=dac[name]                           #This is the document
        
        fire=dad.find_one({},{"_id":0,"user.password":1,"user.email":1,"user.state":1,"user.election circles":1,"user.nation":1,"user.name":1})                            
      
        if fire==None:
            return {"Result":"NO USER FOUND"}
        else:
            try:
                assert fire["user"]["password"]==tes.hexdigest() #Fire dictionary stores the user data   
                a=token_hex(4)
                b=token_hex(4)
                c=+str(a)+str(round(time.time()))+str(b)
                
                me=nd()
                me["auth"]["token"]=c                         #The token that will be linked
                me["user"]["email"]=fire["user"]["email"]     #The email that will be linked
                me["user"]["election circles"]=fire["user"]["election circles"] #The election circles
                me["user"]["state"]=fire["user"]["state"]      #The state is stored
                me["user"]["name"]=fire["user"]["name"]
                
                dab1=db["Tokens"]
                dac1=dab1[fire["user"]["state"]]
                dad1=dac1[c]
                dad1.insert_one(me)          

                return {"Token":c,"election circles":fire["user"]["election circles"],
                       "state":fire["user"]["state"],"nation":fire["user"]["nation"],fire["user"]["name"]}                                                  
            except:
                return {"Error":"either the database flunked or the password"}
    except:
            return{"Error":"Entry/database error"}        
        
@app.route('/api/makequestion',methods=['POST'])
def makepost():
        data=flask.request.data
        data=flask.request.get_json() 
        #####################Check the content here#################################################
        try:
            assert type(data["auth"]["token"])==str           ###Put this in cookie
            assert type(data["auth"]["state"])==str           ###Put this in cookie
            assert type(data["user"]["m_question"])==str
            assert type(data["user"]["d_question"])==str
            assert type(data["meta"]["election circles"])==str
            assert type(data["meta"]["tags"])==list and len(data["meta"]["tags"])<=4
           ## for i in data["user"]["Election circles"]:assert type(i)==str
            assert type(data["user"]["nation"])==str   
            
           ##Make a list for tags which keeps updating 
                
        except:    
            return {"Result":"Stop sending random data type or injection attacks bakayaro"}
        #####################Check the content here#################################################
        try:
             ######################Veriying the token###########################################
             dab=db["Tokens"]
             dac=dab[data["user"]["state"]]
             dad=dac[data["auth"]["token"]]
              
             fire=dad.find_one({},{"_id":0,"user.nation":1,"user.email":1,"user.state":1,"user.election circles":1,"user.name":1})                                                                                                                          
             if fire==None:
                    return {"Error":"User Does not exist"}
           ######################Veriying the token###########################################
             else:   
                assert data["user"]["state"] == fire["user"]["state"]
                assert data["user"]["nation"]== fire["user"]["nation"]
                assert data["meta"]["election circles"] in fire["user"]["election circles"]
        except:         
                return {"Error":"SHit went south"}
        try:        
                me=nd()
                me["q"]["m_question"]=data["user"]["m_question"]
                me["q"]["d_question"]=data["user"]["d_question"]
                me["q"]["tags"]=data["meta"]["tags"]
                me["q"]["election circles"]=data["meta"]["election circles"]
                me["q"]["time_stamp"]=str(round(time.time()))
                me["q"]["followers"]=1
                me["q"]["author"]=fire["user"]["name"]
                me["auth"]["users"]=[fire["user"]["email"],"mithravishwa37@gmail.com"]      #Add the ability to add security staff                                          
                a=str(token_hex(2))+str(round(time.time()))+str(token_hex(2))                
                
                dab=db["Feed"]
                dac=dab[fire["user"]["state"]]
                dad=dac[a]
                
                dad.insert_one(me)  
                                        
                return {"Result":"okay"}
        except:                       
            return {"error":"Don't know wtf went wrong"}
  

@app.route('/api/makesolution',methods=['POST'])
def makecomment():   
    data=flask.request.data
    data=flask.request.get_json()
    
    try:
        assert data["auth"]
        
        
        
        
        
        
        

@app.route('/api/makecomment',methods=['POST'])
def makecomment():   
    data=flask.request.data
    data=flask.request.get_json()
    
    try:
        assert type(data["auth"]["token"])==str
        assert type(data["user"]["comment"])==str
        assert type(data["user"][""])
        
        
        
        
        
    
    
    
    
    
    
    
    
    
        

if __name__ == '__main__':
   app.run()