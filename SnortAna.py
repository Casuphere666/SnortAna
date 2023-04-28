##############
#  SnortAna  #
##############

######################
# Author  : Casuphere
# Version : 0.01
######################

import re

filename = ".\\Snort\\snortrules-snapshot-3034\\rules\\snort3-browser-firefox.rules"

showRule = 1  #if 0, only output proto statistics

showTuple = 1  #if 1, output tuple for each rule
showStr = 1    #if 1, output Str for each rule
showError = 1  #if 1, output error rule


class SnortRule:
    def __init__(self,rid,line):
        self.rid   = rid
        self.line  = line
        self.Tuple = self.getTuple(line)
        self.Str   = self.getStr(line)

    def getTuple(self,line):
        cutline = line.split(' ')
        L = [2,3,5,6,1]
        R = [5,6,2,3,1]
        Tuple=[]
        Tuple.append("OK")
        if(cutline[4]=="->"):
            for seq in R:
                Tuple.append(cutline[seq])
        elif(cutline[5]=="<-"):
            for seq in L:
                Tuple.append(cutline[seq])
        else: #unknown direction
                Tuple[0]="Unknown Direction"
                return Tuple
        self.Proto = Tuple[1]
        return Tuple  

    def getStr(self,line):
        pcre_rem = "pcre:\"([^\"]*)\""
        cont_rem = "content:\"([^\"]*)\""
        pcrelist = re.findall(pcre_rem, line)
        contlist = re.findall(cont_rem,line)
        
        Str = []
        for item in pcrelist:
            Str.append(item)
        for item in contlist:
            Str.append(item)
        return Str
    
    rid = 0
    line = ""
    Tuple = []  #Status(OK/Err),srcIP,dstIP,srcPt,dstPt,proto
    Str = []
    Proto = ""

Rcnt = 0
Ana_error_cnt = 0
#Ana_error_list = []
#Ana_tuple_list = []
#Ana_str_list=[]
Ana_proto_dic = {}

def showAna(rulelist):
    print("----------------SnortAna--------------")
    print("Rule File:",filename)
    print("Total Rule:",Rcnt)
    print("Ana Failed:",Ana_error_cnt)
    print("--------------------------------------")
    print("[Proto]")
    for item in Ana_proto_dic:
        print("<",item,">:",Ana_proto_dic[item])

    print("[Rules]")
    if(showRule):
        for rule in rulelist:
            print("R",rule.rid,": ",end="")
            #print(rule.Tuple[0])
            if(rule.Tuple[0]=="OK"):
                if(showTuple):
                    print(rule.Tuple[1:],"   ",end="")
                if(showStr):
                    print(rule.Str,"   ")
            else:
                if(showError):
                    print("R",rule.rid," ErrLine:",rule.line)
        

def rulesAna(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    global Rcnt
    global Ana_error_cnt
    rulelist = []
    for line in lines:
        if not(line[0]=='a' and line[1]=='l'):
            continue
        new_rule = SnortRule(Rcnt,line)
        rulelist.append(new_rule)
        Rcnt+=1
    for rule in rulelist:
        if(rule.Tuple[0]=="OK"):
            if(rule.Proto in Ana_proto_dic):
                Ana_proto_dic[rule.Proto]+=1
            else:
                Ana_proto_dic[rule.Proto]=1
        else:
            Ana_error_cnt+=1
            
    showAna(rulelist)

    
rulesAna(filename)


