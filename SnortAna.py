##############
#  SnortAna  #
##############

######################
# Author  : Casuphere
# Version : 0.11
######################

import re
import os

# rdic = "..\\Snort\\snortrules-snapshot-3034\\rules"
rdic = "..\\Snort\\snortrules-snapshot-3034\\rules\\snort3-app-detect.rules"

showRule = 1  # if 0, only output statistics
savetoFile = 0  # if 1,the conent will save to file

showTuple = 0  # if 1, output tuple for each rule
showStr = 0  # if 1, output Str for each rule
showError = 1  # if 1, output error rule


class SnortRule:
    def __init__(self, rid, line):
        self.rid = rid
        self.line = line
        self.Tuple = self.getTuple(line)
        self.Str = self.getStr(line)

    def getTuple(self, line):
        cutline = line.split(' ')
        L = [2, 3, 5, 6, 1]
        R = [5, 6, 2, 3, 1]
        Tuple = ["OK"]
        if (cutline[4] == "->"):
            for seq in R:
                Tuple.append(cutline[seq])
        elif (cutline[4] == "<-"):
            for seq in L:
                Tuple.append(cutline[seq])
        elif (cutline[4] == "<>"):  # any direction,we regard it as ->
            for seq in R:
                Tuple.append(cutline[seq])
        elif (cutline[2] == "("):  # No need for tuple
            ign = 4
            while (ign):
                Tuple.append("/")
                ign -= 1
            Tuple.append(cutline[1])
        else:  # unknown type
            Tuple[0] = "Unknown Direction"
            return Tuple
        self.Proto = Tuple[5]
        return Tuple

    def getStr(self, line):
        pcre_rem = "pcre:\"([^\"]*)\""
        cont_rem = "content:\"([^\"]*)\""
        pcrelist = re.findall(pcre_rem, line)
        contlist = re.findall(cont_rem, line)
        Str = []
        pcrefile = 0
        contfile = 0
        if (savetoFile):
            pcrefile = open("pcre.txt", 'a+')
            contfile = open("cont.txt", 'a+')
        for item in pcrelist:
            Str.append(item)
            self.pcrecnt += 1
            if (savetoFile):
                pcrefile.write(item + "\n")
        for item in contlist:
            Str.append(item)
            self.contcnt += 1
            if (savetoFile):
                contfile.write(item + "\n")
        if (savetoFile):
            pcrefile.close()
            contfile.close()
        return Str

    rid = 0
    line = ""
    Tuple = []  # Status(OK/Err),srcIP,dstIP,srcPt,dstPt,proto
    Str = []
    pcrecnt = 0
    contcnt = 0
    Proto = ""


Rcnt = 0
Ana_error_cnt = 0
# Ana_error_list = []
# Ana_tuple_list = []
# Ana_str_list=[]
Ana_proto_dic = {}


def showAna(rulelist):
    print("----------------SnortAna--------------")
    print("Total Rule:", Rcnt)
    print("Ana Failed:", Ana_error_cnt)
    print("--------------------------------------")
    print("[Proto]")
    for item in Ana_proto_dic:
        print("<", item, ">:", Ana_proto_dic[item])
    pcrecnt = 0
    contcnt = 0
    for rule in rulelist:
        pcrecnt += rule.pcrecnt
        contcnt += rule.contcnt
    print("[Pcre] \n", pcrecnt)
    print("[Cont] \n", contcnt)

    if (showRule):
        print("[Rules]")
        for rule in rulelist:
            if (rule.Tuple[0] == "OK"):
                if (showTuple):
                    print("R", rule.rid, ": ", end="")
                    print(rule.Tuple[1:], "   ", end="")
                if (showStr):
                    print(rule.Str, "   ", end="")
                if (showTuple or showStr):
                    print()
            else:
                if (showError):
                    print("R", rule.rid, " ErrLine:", rule.line)


def rulesAna(dic):
    lines = []
    if (os.path.isdir(dic)):
        Fcnt = 0
        for filename in os.listdir(dic):
            filepath = os.path.join(dic, filename)
            if (os.path.isfile(filepath) and filepath.endswith('.rules')):
                # print("[Ruleset Found]",filepath)
                with open(filepath, 'r') as f:
                    lines += f.readlines()
                Fcnt += 1
        print("[SnortAna] Work for ", Fcnt, " rulesets in ", dic)
    elif (os.path.isfile(dic)):
        with open(dic, 'r') as f:
            lines = f.readlines()
        print("[SnortAna] Work for a single ruleset: ", dic)
    else:
        print("[Err]Invalid File Path. It should be an exist file or a folder")

    global Rcnt
    global Ana_error_cnt
    rulelist = []
    for line in lines:
        if not (line[0] == 'a' and line[1] == 'l'):
            continue
        new_rule = SnortRule(Rcnt, line)
        rulelist.append(new_rule)
        Rcnt += 1
    for rule in rulelist:
        if (rule.Tuple[0] == "OK"):
            if (rule.Proto in Ana_proto_dic):
                Ana_proto_dic[rule.Proto] += 1
            else:
                Ana_proto_dic[rule.Proto] = 1
        else:
            Ana_error_cnt += 1

    showAna(rulelist)


rulesAna(rdic)
