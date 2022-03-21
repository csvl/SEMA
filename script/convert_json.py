import sys
import json


f = open('temp.txt','r')
signature = f.read()

chop_sig = signature.split('\n')
returns = chop_sig[0].split(' ')[0]
name = chop_sig[0].split(' ')[1][:-1]
cc = "__stdcall"
returns_float = False


Dic = {}
Dic["cc"] = cc
Dic["returns"] = returns
Dic["returns_float"] = returns_float
Dic["name"] = name
is_float = False
arg = []
no_arg = True
for l in chop_sig[1:-2]:
    no_arg=False
    filtered = list(filter(None,l.split(' ')))
    print(filtered)
    type_arg = filtered[0]
    name_arg = filtered[1].replace(',','')
    
    print(type_arg)
    print(name_arg)
    dic_arg = {}
    dic_arg["type"] = type_arg
    dic_arg["name"] = name_arg
    dic_arg["is_float"] = is_float
    arg.append(dic_arg)

if no_arg:
    if name[-1] == ')' and name[-2]=='(':
        name = name[:-2]
        Dic["name"] = name
        dic_arg = {}
        dic_arg["type"] = "void"
        dic_arg["name"] = None
        dic_arg["is_float"] = False
        arg.append(dic_arg)
Dic["arguments"] = arg        

print(json.dumps(Dic,indent=4))
f.close()
with open(sys.argv[1], "r") as fp:
    #return json.load(fp)
    #fp = open(sys.argv[1], "r") 
    jsonfile = json.load(fp)
with open(sys.argv[1], "r") as fp:

    jsonfile_new = json.load(fp)

with open(sys.argv[1], "w") as fp:
    try:
        jsonfile_new[sys.argv[2]] = Dic
        json.dump(jsonfile_new,fp,indent=4)
    except:
        print('error keeping old version')
        json.dump(jsonfile,fp,indent=4)
    exit(0)
    
