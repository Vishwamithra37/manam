#This works fine
from nested_dictionaries import NestedDictionaries as nd
import flask
import pymongo as pym
from hashlib import sha256,md5
from Crypto.Random import get_random_bytes
from secrets import token_hex
import time
from bson.objectid import ObjectId
import json


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
accemails=["gmail","yahoo","rocketmail","outlook"]                    #Add in acceptable email domains
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
                assert len(data["user"]["election circles"])<=10 and type(data["user"]["election circles"])==list                                   #Defending against stupid attacks
                for i in data["user"]["election circles"]:assert type(i)==str
                assert len(data["user"]["phone"])<=10 and len(data["user"]["phone"])>8 and type(data["user"]["phone"])==str #Defending against stupid attacks
                assert type(data["user"]["state"])==str
                assert type(data["user"]["nation"])==str and len(data["user"]["nation"])<=25
                assert type(data["user"]["name"])==str and 3<len(data["user"]["name"])<20 
                assert data["user"]["nation"] in countries ###Change to database
                assert data["user"]["dateofbirth"]==str and len((data["user"]["dateofbirth"]).split('/'))==3


        except:
                return {"Error":"Error in assertions"}   
        
        


        try:
            x=data["user"]["email"].split("@")#Seperating the username from domain
            x1=x[1].split(".")                #seperating the domain and .
            name=x[0]                         #Assingning the starting name to the name
            edomain=x1[0]                     #Assigning the domain to the domain
            assert len(name.split('+'))==1    ###Defending against idioittto
            assert len(name.split('.'))==1    ###Defending against idioittto
             
            dab=db["users"]          #This is the users data database
            dac=dab[data["user"]["state"]]                     #This is a collection
            assert dac.find_one({"user.email":data["user"]["email"]})==None          #Checking for existing users
        except:
            return {"Error":"User already exists"}
        
        
        #####################Check the content here################################################# 
        dab=db["states_list"]
        dac=dab["list"]

        assert dac.find_one({"state":data["user"]["state"]},{"_id":0,"state":1})!=None
        

        
        
        dab=db["election circles"]
        dac=dab[data["user"]["state"]]
        

        for i in data["user"]["election circles"]:
            fire=dac.find_one({"ec":i},{"_id":0,"ec":1})
            if fire==None:
                return {"error":"Election circle not supported"}
            

        dob=(data["user"]["dateofbirth"]).split(3)
        assert int(dob[0])<=31
        assert int(dob[1])<=12
        assert (((time.localtime(time.time())).tm_year)-100)<int(dob[2])<(((time.localtime(time.time())).tm_year)-12) 

        #################Expected contents(Add Here to upgrade)#####################################################    
        me=nd()
        me["user"]["email"]=data["user"]["email"]                                          #1
        me["user"]["password"]=data["user"]["password"]                                    #2
        me["user"]["age"]=data["user"]["age"]                                              #3
        me["user"]["sex"]=data["user"]["sex"]                                              #4
        me["user"]["occupation"]=data["user"]["occupation"]                                #5 
        me["user"]["election circles"]=data["user"]["election circles"]                    #6
        me["user"]["state"]=data["user"]["state"]                                          #7
        me["user"]["phone"]=data["user"]["phone"]                                          #8
        me["user"]["nation"]=data["user"]["nation"]                                        #9
        me["user"]["name"]=data["user"]["name"]                                            #10
        me["user"]["dob"]=dob                                                              #11
        
        #################Expected contents(Add Here to upgrade)#####################################################          

                

        

        
        assert edomain in accemails   #Hopefully he has email which is verified    
        
        tes=md5((data["user"]["password"]).encode('utf-8'))
        me["user"]["password"]=tes.hexdigest()
        
        
        dab=db["users"]          #This is the users data database
        dac=dab[me["user"]["state"]]                     #This is a collection
        
        
 
        
        dac.insert_one(me)                   #Inserts the email and password into the required collection
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
        assert type(data["user"]["password"])==str and len(data["user"]["password"])==19
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
        
        
        fire=dac.find_one({"user.email":data["user"]["email"]},
                          {"_id":0,"user.password":1,"user.email":1,
                          "user.state":1,"user.election circles":1,
                          "user.nation":1,"user.name":1})                            
      
        if fire==None:
            return {"Result":"NO USER FOUND"}
        else:
            try:
                assert fire["user"]["password"]==tes.hexdigest() #Fire dictionary stores the user data   
                a=token_hex(4)
                b=token_hex(4)
                c=str(a)+str(round(time.time()))+str(b)
                
                me=nd()
                me["auth"]["token"]=c                         #The token that will be linked
                me["user"]["email"]=fire["user"]["email"]     #The email that will be linked
                me["user"]["election circles"]=fire["user"]["election circles"] #The election circles
                me["user"]["state"]=fire["user"]["state"]      #The state is stored
                me["user"]["name"]=fire["user"]["name"]
                
                dab1=db["Tokens"]
                dac1=dab1[fire["user"]["state"]]
                
                dac1.insert_one(me)          

                return {"Token":c,
                       "election circles":fire["user"]["election circles"],
                       "state":fire["user"]["state"],
                       "nation":fire["user"]["nation"],
                       }                                                  
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
            assert type(data["auth"]["nation"])==str          ###Put this in cookie
            
           ##Make a list for tags which keeps updating 
                
        except:    
            return {"Result":"Stop sending random data type or injection attacks bakayaro"}
        #####################Check the content here#################################################
        try:
             ######################Veriying the token###########################################
             dab=db["Tokens"]
             dac=dab[data["user"]["state"]]
                          
             fire=dac.find_one({"auth.token":data["auth"]["token"]},{"_id":0,"user.nation":1,"user.email":1,"user.state":1,"user.election circles":1,"user.name":1})                                                                                                                          
             if fire==None:
                    return {"Error":"User Does not exist"}
           ######################Veriying the token###########################################
             else:   
                assert data["user"]["state"] == fire["user"]["state"]
                assert data["auth"]["nation"]== fire["user"]["nation"]
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
                me["q"]["state"]=fire["user"]["state"]
                me["q"]["nation"]=fire["user"]["nation"]
                me["q"]["noofanswers"]=0
                me["auth"]["users"]=[fire["user"]["email"],"mithravishwa37@gmail.com"]      #Add the ability to add security staff                                          
                me["auth"]["m_user"]=fire["user"]["email"]   
                
                
                
                    
                         


                dab=db["feed"]
                dac=dab[fire["user"]["state"]]
                
                
                dac.insert_one(me)  
                                      
                dab=db["followers"]
                dac=dab[fire["user"]["state"]]
                tbf=nd()
                tbf["q"]["hash"]=me["_id"]
                tbf["election circles"]=me["q"]["election circles"]
                dac.insert_one(tbf)




                return {"Result":"okay","hash":str(me["_id"])}
        except:                       
            return {"error":"Don't know wtf went wrong"}
  

@app.route('/api/makesolution',methods=['POST'])
def makesolution():   
    data=flask.request.data
    data=flask.request.get_json()
    
    try:
        assert type(data["auth"]["token"])==str
        assert type(data["s"]["solution"])==str
        assert type(data["q"]["hash"])==str
        assert type(data["auth"]["state"])==str
    except:
        return{"error":"Honey, stop trying and go to mama. *-* "}
        ######################Veriying the token###########################################
    try:
             
        dab=db["Tokens"]
        dac=dab[data["auth"]["state"]]
                          
        fire=dac.find_one({"auth.token":data["auth"]["token"]},{"_id":0,"user.nation":1,"user.email":1,"user.state":1,"user.election circles":1,"user.name":1})                                                                                                                          
        if fire==None:
            return {"Error":"User Does not exist"}
        else:
            dab=db["feed"]
            dac=dab[fire["user"]["state"]]

            fire2=dac.find_one({ObjectId(data["q"]["hash"])},
                               {"_id":0,"q.state":1,"q.election circles":1,"q.nation":1})                                                        



            assert fire2["q"]["state"] == fire["user"]["state"]
            assert fire2["q"]["nation"]== fire["user"]["nation"]
            assert fire2["q"]["election circles"] in fire["user"]["election circles"]
    ######################Veriying the token###########################################

            dab=db["solutions"]
            dac=dab[fire["user"]["state"]]

            assert dac.find_one({"q.hash":data["q"]["hash"],"auth.m_user":fire["user"]["email"]})==None

            me=nd()
            me["q"]["hash"]=data["q"]["hash"]
            me["s"]["solution"]=data["s"]["solution"]
            me["s"]["author"]=fire["user"]["name"]
            me["s"]["time_stamp"]=str(round(time.time()))
            me["s"]["upvotes"]=0
            me["s"]["downvotes"]=0
            me["s"]["election circles"]=fire2["q"]["election circles"]
            me["s"]["state"]=fire2["q"]["state"]
            me["s"]["nation"]=fire2["q"]["nation"]
            me["s"]["comments"]="no"
            me["auth"]["users"]=["mithravishwa37@gmail.com",fire["user"]["email"]]
                       
            dac.insert_one(me)
          
            dab=db["feed"]
            dac=dab[fire["user"]["state"]]

            dac.update_one({"_id":ObjectId(me["q"]["hash"])},{"$inc":{"q.noofanswers":1}})###



            return {"ok":"Done","hash":str(me["_id"])}
    except:
        return {"error":"Already wrote a solution"}
      


############IN the state, there are election circles, In which there are multiple elections. 
#So check the make question route again and add the elections





@app.route('/api/makecomment',methods=['POST'])
def makecomment():   
    data=flask.request.data
    data=flask.request.get_json()
    
    try:
        assert type(data["auth"]["token"])==str
        assert type(data["user"]["comment"])==str
        assert type(data["s"]["hash"])==str
        assert type(data["auth"]["state"])==str
    except:
        return {"error":"Check if every shit is the right data type"}
        ######################Veriying the token###########################################
    try: 
        dab=db["Tokens"]
        dac=dab[data["auth"]["state"]]
                          
        fire=dac.find_one({"auth.token":data["auth"]["token"]},
                          {"_id":0,"user.nation":1,"user.email":1,
                          "user.state":1,"user.election circles":1,
                          "user.name":1})                                                                                                                          
        if fire==None:
            return {"Error":"User Does not exist"}
        else:
            ######################Veriying the token###########################################
            dab=db["solutions"]
            dac=dab[fire["user"]["state"]]

            fire2=dac.find_one({ObjectId(data["s"]["hash"],)},
                               {"_id":0,"s.state":1,"s.election circles":1,"s.nation":1
                               ,"q.hash":1})                                                        
            
            assert fire2["s"]["state"] == fire["user"]["state"]
            assert fire2["s"]["nation"]== fire["user"]["nation"]
            assert fire2["s"]["election circles"] in fire["user"]["election circles"]

    except:  
        return {"error":"Some ridiculous error"}

    try:
        dab=db["comments"]
        dac=dab[fire["user"]["state"]]
        
        me=nd()
        me["s"]["hash"]=data["s"]["hash"]
        me["c"]["comment"]=data["user"]["comment"]
        me["c"]["author"]=fire["user"]["name"]
        me["c"]["time_stamp"]=str(round(time.time()))
        me["c"]["upvotes"]=0
        me["c"]["downvotes"]=0
        me["c"]["state"]=fire2["s"]["state"]
        me["c"]["election circles"]=fire2["s"]["election circles"]
        me["c"]["nation"]=fire2["s"]["election circles"]
        me["auth"]["emails"]=["mithravishwa37@gmail.com",fire["user"]["email"]]
        me["c"]["comments"]="no"
        
        dac.insert_one(me)


        dab=db["solutions"]
        dac=dab[fire["user"]["state"]]

        dac.update_one({"_id":ObjectId(me["s"]["hash"])},{"$set":{"s.comments":"yes"}})

        return {"OK":"Operation successfull"}

    except:         
        return {"error":"Something went wrrrroooong"}




@app.route('/api/makereply',methods=['POST'])
def makecommentreply():
    data=flask.request.data
    data=flask.request.get_json()
    try:
        assert type(data["auth"]["token"])==str
        assert type(data["user"]["comment"])==str
        assert type(data["c"]["hash"])==str
        assert type(data["auth"]["state"])==str
    except:

        return {"error":"Check if every shit is the right data type"}
    
        ######################Veriying the token###########################################
    try: 
        dab=db["Tokens"]
        dac=dab[data["auth"]["state"]]
                          
        
        fire=dac.find_one({"auth.token":data["auth"]["token"]},
                          {"_id":0,"user.nation":1,"user.email":1,
                          "user.state":1,"user.election circles":1,
                          "user.name":1})                                                                                                                          
        
        if fire==None:
            return {"Error":"User Does not exist"}
        else:
    ######################Veriying the token###########################################
            dab=db["comments"]
            dac=dab[fire["user"]["state"]]
            fire2=dac.find_one({ObjectId(data["c"]["hash"])},
                               {"_id":0,"c.state":1,"c.election circles":1,"c.nation":1})
            assert fire2["c"]["state"] == fire["user"]["state"]
            assert fire2["c"]["nation"]== fire["user"]["nation"]
            assert fire2["c"]["election circles"] in fire["user"]["election circles"]
           
            me=nd()
            me["c"]["hash"]=data["c"]["hash"]
            me["c"]["comment"]=data["user"]["comment"]
            me["c"]["time_stamp"]=str(round(time.time()))
            me["c"]["upvotes"]=0
            me["c"]["downvotes"]=0
            me["c"]["comments"]="no"
            me["c"]["state"]=fire2["c"]['state']
            me["c"]["election circles"]=fire2["c"]["election circles"]
            me["c"]["nation"]=fire2["c"]["nation"]
            me["auth"]["emails"]=["mithravishwa37@gmail.com",fire["user"]["email"]]

            dac.insert_one(me)
               
            dac.update_one({"_id":ObjectId(data["c"]["hash"])},{"$set":{"c.comments":"yes"}})   
            return {"ok":"Comment posted"}
    except:
        return {"error":"Probably not of the same region?"}
            
#########################From here we set on on editing the adventures###################################
#########################################################################################################
        
@app.route('/api/feed',methods=['POST'])
def feeder():   
    data=flask.request.data
    data=flask.request.get_json()
            
    try:
        assert type(data["auth"]["token"])==str
        assert type(data["auth"]["state"])==str 
        assert type(data["user"]["election circles"])==str
    except:
        return {"error":"Check if every shit is the right data type"}

    try: 
        dab=db["Tokens"]
        dac=dab[data["user"]["state"]]
                          
        
        fire=dac.find_one({"auth.token":data["auth"]["token"]},
                          {"_id":0,"user.nation":1,"user.email":1,
                          "user.state":1,"user.election circles":1,
                          "user.name":1})  
    
        assert data["auth"]["state"]==fire["user"]["state"]
        assert data["user"]["election circles"] in fire["user"]["election circles"]  

        if fire==None:
            return {"Error":"User Does not exist"}
        else:
            dab=db["feed"]
            dac=dab[fire["user"]["state"]]
                 
             ####Change this as more questions come into the feed, to 
             ####make it promote new questions then most followed, then    
            fire2=dac.find({"election circles":data["user"]["election circles"]},
                          {"_id":1,"q.m_question":1,"q.d_question":1}).limit(4)
            
            que=nd()
            count=0
            
            for ques in fire2:
                count=count+1
                que["question_"+str(count)]["hash"]=str(ques["_id"])
                que["question_"+str(count)]["m_question"]=ques["q"]["m_question"]
                que["question_"+str(count)]["d_question"]=ques["q"]["d_question"]
                
            return que    
    except:
        return {"error":"Probably user not found :("}

@app.route('/api/question/<state_hash_ec>',methods=['GET'])
def question(state_hash_ec):
    assert type(state_hash_ec) == str  #Use compound index
    s=state_hash_ec.split('_')
    assert len(s)==3 

    dab=db["feed"]
    dac=dab[s[0]]

    fire=dac.find_one({"_id":ObjectId(s[1]),"election circles":s[2]},
                      {"_id":0,"q.m_question":1,"q.d_question":1,
                      "q.author":1,"q.time_stamp":1,"q.followers":1,"q.noofanswers":1,
                      "q.state":1,"q.election circles":1})

    me=nd()
    me["question"]=fire    
    dab=db["solutions"]
    dac=dab[s[0]]

    fire=dac.find({"election circles":s[2],"q.hash":s[1]},
                  {"_id":1,"s.solution":1,"s.upvotes":1,"s.downvotes":1,
                  "s.author":1,"s.comments":1,"s.time_stamp":1}).limit(5)
    count=0
    for i in fire:
       count=count+1
       me["solution_"+str(count)]=i
       if me["solution_"+str(count)]!=None:
        me["solution_"+str(count)]["_id"]=str(me["solution_"+str(count)]["_id"])
        me["solution_"+str(count)]["s"]["hash"]=me["solution_"+str(count)]["_id"]
        del me["solution_"+str(count)]["_id"]


    return me

def cheker(retch):
    # Checks for token authenticity
    # data["user"]["token"]
    # data["auth"]["state"]
    # data["auth"]["election circles"]
    assert type(retch["user"]["token"])==str
    assert type(retch["auth"]["state"])==str
    assert type(retch["auth"]["election circles"])==str
    dab=db["Tokens"]
    dac=dab[retch["auth"]["state"]]   
    fire=dac.find_one({"auth.token":retch["auth"]["token"]},
                          {"_id":0,"user.nation":1,"user.email":1,
                          "user.state":1,"user.election circles":1,
                          "user.name":1})                                                                                                                              
    if fire==None:
            return None
    else:
            assert (retch["auth"]["state"])==fire["user"]["state"]
            assert (retch["auth"]["election circles"]) in fire["user"]["election circles"]
            return fire

def replier(me):
    a=flask.make_response(me)
    a.headers["Server"]="node.js"
    return a


@app.route('/api/getsolutions',methods=['POST'])
def getsols():
    try:
        a=flask.make_response(json.dumps({"error":"alivolivoli  hai"}))
        a.headers["Server"]="node.js"
        data=flask.request.data
        data=flask.request.get_json()  
        assert data["s"]["skip"]<=7 and data["s"]["skip"]==int

        fire=cheker(data)
        assert fire!=None
    except:      
        return a
    try:
        assert type(data["q"]["hash"])==str
        assert data["q"]["election circles"] in fire["user"]["election circles"]
        assert data["q"]["state"]==fire["user"]["state"]
         
        dab=db["solutions"]
        dac=dab[fire["state"]]

        fire=dac.find({"election circles":data["q"]["election circles"],"q.hash":data["q"]["hash"]},
                  {"_id":1,"s.solution":1,"s.upvotes":1,"s.downvotes":1,
                  "s.author":1,"s.comments":1,"s.time_stamp":1}).skip(data["s"]["skip"])
        me=nd()
        count=0
        for i in fire:
           count=count+1
           me["solution_"+str(count)]=i
           if me["solution_"+str(count)]!=None:
            me["solution_"+str(count)]["_id"]=str(me["solution_"+str(count)]["_id"])
            me["solution_"+str(count)]["s"]["hash"]=me["solution_"+str(count)]["_id"]
            del me["solution_"+str(count)]["_id"]
            
        a=flask.make_response(json.dumps(me))
        a.headers["Server"]="node.js"
        return a
    except: 
        a=flask.make_response({"error":"lost in space"})
        a.headers["Server"]="node.js"
        return a 


@app.route('/api/getcomms',methods=['POST'])
def getcomms():
        a=flask.make_response({"error":"alivolivoli  hai"})
        a.headers["Server"]="node.js"
        data=flask.request.data
        data=flask.request.get_json()  
        #Reqs:
        # data["user"]["token"]-str
        # data["auth"]["state"]-str
        # data["auth"]["election circles"]-str
        # data["c"]["skip"]--int
        # data["s"]["hash"] or data["c"]["hash"]--str
        assert data["c"]["skip"]<=5 and data["c"]["skip"]==int
        fire=cheker(data)
        assert fire!=None   
        dab=db["comments"]       
        try:
            assert type(data["s"]["hash"])==str and len(data["s"]["hash"])>5
            dac=dab[fire["user"]["state"]]
            fire=dac.find({"s.hash":data["s"]["hash"],"c.election circles":data["auth"]["election circles"]},
                     {"_id":1,"c.name":1,"c.time_stamp":1,"c.upvotes":1,"c.downvotes":1,
                     "c.comments":1,"c.election circles":1}).limit(data["c"]["skip"])
            count=0
            me=nd()
            for i in fire:
              count=count+1
              me["comment_"+str(count)]=i
              if me["comment_"+str(count)]!=None:
                me["comment_"+str(count)]["_id"]=str(me["comment_"+str(count)]["_id"])
                me["comment_"+str(count)]["c"]["hash"]=me["comment_"+str(count)]["_id"]
                del me["comment_"+str(count)]["_id"]
              
            a=replier(me)
            return a


        except:    
            assert type(data["c"]["hash"])==str and len(data["c"]["hash"])>5
            dac=dab[fire["user"]["state"]]
            fire=dac.find({"s.hash":data["c"]["hash"],"c.election circles":data["auth"]["election circles"]},
                     {"_id":1,"c.name":1,"c.time_stamp":1,"c.upvotes":1,"c.downvotes":1,
                     "c.comments":1,"c.election circles":1}).limit(data["c"]["skip"])
            count=0
            me=nd()
            for i in fire:
              count=count+1
              me["comment_"+str(count)]=i
              if me["comment_"+str(count)]!=None:
                me["comment_"+str(count)]["_id"]=str(me["comment_"+str(count)]["_id"])
                me["comment_"+str(count)]["c"]["hash"]=me["comment_"+str(count)]["_id"]
                del me["comment_"+str(count)]["_id"]
              
            a=replier(me)
            return a          



@app.route('/api/follow',methods=['POST'])
def follows():
        a=flask.make_response({"error":"alivolivoli  hai"})
        a.headers["Server"]="node.js"
        data=flask.request.data
        data=flask.request.get_json()  
        fire=cheker(data)
        assert fire!=None

        #############################################################################################
        assert type(data["q"]["hash"])==str

        try:
            dab=db["followers"]
            dac=dab[fire["user"]["state"]]        

            assert dac.find_one({"election circles":data["auth"]["election circles"],"q.hash":data["q"]["hash"]},
                        {"_id":0,"q.followers."+fire["user"]["email"]:1})!=None

            dac.update_one({"election circles":data["auth"]["election circles"],"q.hash":data["q"]["hash"]},
                        {"$unset":{"q.followers":{fire["user"]["email"]:fire["user"]["email"]}}})
            

            dab=db["feed"]
            dac=dab[fire["user"]["state"]]

            dac.update_one({ObjectId(data["q"]["hash"])},{"$inc":{"q.followers":-1}})


            return {"Operation":"Successfully unfollowed"}

        except:  

            dab=db["followers"]
            dac=dab[fire["user"]["state"]]
            
        

            dac.update_one({"election circles":data["auth"]["election circles"],"q.hash":data["q"]["hash"]},
                        {"$set":{"q.followers":{fire["user"]["email"]:fire["user"]["email"]}}})

            ###############################################################################################

            dab=db["feed"]
            dac=dab[fire["user"]["state"]]

            dac.update_one({ObjectId(data["q"]["hash"])},{"$inc":{"q.followers":1}})

            #############################################################################################   

                
            return {"Operation":"Successful"}    
            ##################NEEDS TO BE WRITTEN########################################################

          
@app.route('/api/notifics',methods=['POST'])
def notifs():    
        a=flask.make_response({"error":"alivolivoli  hai"})
        a.headers["Server"]="node.js"
        data=flask.request.data
        data=flask.request.get_json()  
        fire=cheker(data)
        assert fire!=None

        dab=db["all_notifs"]
        dac=dab[fire["user"]["state"]]
        
        r1=dac.find_one({"user.email":fire["user"]["email"]},
                        {"_id":0,"notif.status":1,"notif.count":1,"notif.list":1})
                                 ##YES or NO
        return r1
        




@app.route('/api/edit_prof',methods=['POST'])
def editprof():
        a=flask.make_response({"error":"alivolivoli  hai"})
        a.headers["Server"]="node.js"
        data=flask.request.data
        data=flask.request.get_json()  
        fire=cheker(data)
        assert fire!=None

        v1=["password","phone","occupation"]
########################ADD CAPTCHA###################################################
        assert type(data["edit"]["role"])==str
        assert data["edit"]["role"] in v1
        count=0
         
        v2=data["edit"][data["edit"]["role"]]
        v3=data["edit"]["role"]

        for j in v1:
            count=1+count
            if j==v3 and count==1:
                assert type(v2)==str and len(v2)==19 #password
                tes=md5((v2).encode('utf-8'))
                v4=tes.hexdigest()
            elif j==v3 and count==2:
                assert 8<len(v2)<=10 
                v4=v2
            elif j==v3 and count==3:
                assert type(v2)==str
                v4=v2
            dab=db["users"]                         #This is the database
            dac=dab[fire["user"]["state"]]          #This is a collection        

            dac.update({"user.email":fire["user"]["email"]},{"$set":{v3:v4}})    
        
            return {"Operation":"successful"}

@app.route('/api/state_list/<nation>',methods=['GET'])
def stae_list(nation):
    dab=db["state_list"]
    dac=dab[nation]
    r=dac.find()
    a=[]
    for j in r:
        a.append(j["state"])
    return {"states":a}

@app.route('/api/election_circles/<state>',methods=['GET'])
def stae_list(state):
    dab=db["election circles"]
    dac=dab[state]
    r=dac.find()
    a=[]
    for j in r:
        a.append(j["election circles"])
    return {"election circles":a}    


#Databases required still:
#  1)Upvotes downvotes user ids     #Hidden and only visible to us.
#  2)Followers                      #Hidden and only visible to us and the users
#  3)Meta in user profile           Visble to users

##Need to update the makequestion, make reply, comment and make solution options
       

    








           

        
        
    
    
    
    
    
    
    
    
    
        

if __name__ == '__main__':
   app.run()